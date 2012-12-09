/*
    sws.c -- a simple web server

    Developer : Bo Yu (boyu2011@gmail.com)
*/

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <syslog.h>

//#define DEBUG

/* buggy: how to solve large file issue */
#define MAX_LEN 99999
#define PATH_LEN 999
#define STR_LEN 999

/*
	Log every request in a slight variation of Apache's so-called
	"common" format: '%a %t "%r" %>s %b'

	%a The remote IP address.
	%t The time the request was received (in GMT).
	%r The (quoted) first line of the request.
	%>s The status of the request.
	%b Size of the response in bytes. Ie, "Content-Length".
*/
struct log_info
{
	char remote_ip_addr [100];
	char time_request_received [100];
	char first_line_of_request [100];
	char status_of_request [100];
	char size_of_response [100];
};

struct log_info g_log_info;

extern char ** environ;

/* 
    command line option flags
*/

int d_flag = 0;     /* enter debugging mode. That is, do not daemonize,
                       only accept one connection at a time and enable
                       logging stdout. */
int h_flag = 0;     /* print usage, and exit. */ 
int c_flag = 0;     /* -c dir, allow execution of CGIs from the given
                       directory (relative to the document root). 
                       See CGIs for details. */
int i_flag = 0;     /* -i address, bind to the given IPv4 or IPv6
                       address. If no provided, sws will listen on all
                       IPv4 and IPv6 addresses on this host. */
int l_flag = 0;     /* -l file, log all requests to the given file.
                       See LOGGING for details. */
int p_flag = 0;     /* -p port, listen on the given port. If not
                       provided, sws will listen on port 8080. */
int s_flag = 0;     /* -s dir -k key, enable "secure" mode for the given
                       directory. That is, encrypt all content from this
                       directory with the given key. See ENCRYPTION for
                       details. */
int k_flag = 0;

/*
    global variables
*/

int  g_port = 0;     			 /* port number */
char g_ip_addr_str [MAX_LEN];    /* ip address got from -i */
char g_dir_path [PATH_LEN];		 /* serve content from given directory */
char g_cgi_dir_path [PATH_LEN];	 /* allow execution of CGIs from
									the given directory */
char g_log_file [PATH_LEN];		 /* log all requests to the given file */

/*
    functions
*/

void usage()
{
    printf ( "sws -- a simple web server\n" );
    printf ( "Usage: sws [-dh] [-c dir] [-i address] [-l file] " );
	printf ( "[-p port] [-s dir -k key] dir\n" );
}

char * get_current_timestamp ( char * time_str, size_t time_str_len )
{
	struct	tm *tm;
	time_t	now;

	now = time(NULL);
	tm = gmtime(&now);
	strftime(time_str, time_str_len, "%a, %d %b %Y %H:%M:%S GMT", tm);
	return time_str;
}

/*
	Determine command line options.
*/

void parse_cmd_opt ( int argc, char ** argv )
{
    int ch;

    while ( ( ch = getopt ( argc, argv, "dhc:i:l:p:s:k:" ) ) != -1 )
    {
        switch (ch)
        {
            case 'd':
                d_flag = 1;
                break;

            case 'h':
                h_flag = 1;
                usage();
                exit(0);
                break;

            case 'c':
                c_flag = 1;
				strcpy ( g_cgi_dir_path, optarg );
                break;

            case 'i':
                i_flag = 1;
                strcpy ( g_ip_addr_str, optarg );
                break;

            case 'l':
                l_flag = 1;
				strcpy ( g_log_file, optarg );
                break;

            case 'p':
                p_flag = 1;
                g_port = atoi ( optarg );
                break;

            case 's':
                s_flag = 1;
                break;

            case 'k':
                k_flag = 1;
                break;

            default:
                usage();
                exit(1);
        }
    }

    argc -= optind;
    argv += optind;

	if ( argc == 1 )	/* the last argument should be dir */
	{
#ifdef DEBUG
		printf ( "[DEBUG] Dir Argument: %s\n", *argv );
#endif
		strcpy ( g_dir_path, *argv );
	}
	else
	{
		usage();
		exit(1);
	}
}

/* 
    get ip type ( ipv4/ipv6 )
	return 0 means listen on all Ipv4 and Ipv6 addresses on this host
	return 1 means a valid Ipv4 address
	return 2 means a valid Ipv6 address
	return -1 means an error arise
*/

int determine_ip_type ( char * ip_addr )
{
    uint32_t ipv4_dest;
    uint8_t ipv6_dest[16];
    int ret;
   
    if ( !i_flag )
    {
        return 0;   /* listen on all IPv4&IPv6 addresses on this host */
    }

	/* Convert a presentation format address to network format. */
    ret = inet_pton ( AF_INET, ip_addr, &ipv4_dest );

    if ( ret == 1 ) 
	{
        return 1;	/* a valid ipv4 address */

    }
    else
    {
        ret = inet_pton ( AF_INET6, ip_addr, ipv6_dest );
        
        if ( ret == 1 )         
		{
            return 2;	/* a valid ipv6 address */
        }
    }
    
    return -1;   /* error */
}

/*
	Read the first line ( request line ) from http request
*/

ssize_t read_request_line ( int fd, void * userbuf, size_t maxlen )
{
	int n, read_cnt;
	char c;
    char * bufp = userbuf;

    for ( n = 1; n < maxlen; n++ )
    {
        if ( (read_cnt = read ( fd, &c, 1 )) == 1 )
        {
            *bufp++ = c;
            if ( c == '\n' )
            {
                break;
            }
        }
        else if ( read_cnt == 0 )
        {
            if ( n == 1 )
                return 0;   /* EndOfFile, no data read */
            else
                break;      /* EndOfFile, data was read */
        }
        else
        {
            return -1;      /* error */
        }
    }
	
	*(bufp-2) = '\n';
	*(bufp-1) = '\0';	/* replace '\n' */
    *bufp = 0;
    return n;
}

/*
    send error message to client side
*/

void send_client_error ( int fd, char * error_cause, char * error_number,
                    char * error_reason_phrase )
{
    char buf [MAX_LEN];
    char body [MAX_LEN];

    /* build the HTTP response body */
    sprintf ( body, "<html><title>Error</title>\r\n" );
    sprintf ( body, "%s%s: %s\r\n", body, error_number, error_reason_phrase );
    sprintf ( body, "%s<br/>%s\r\n", body, error_cause );
    sprintf ( body, "%s<hr>Simple Web Server\r\n", body );

    /* write the HTTP response */
    sprintf ( buf, "HTTP/1.0 %s %s\r\n", error_number, error_reason_phrase );
    if ( write ( fd, buf, strlen(buf) ) != strlen (buf) )
    {
        perror ( "write1" );
    }
    sprintf ( buf, "Content-type: text/html\r\n" );
    if ( write ( fd, buf, strlen(buf) ) != strlen (buf) )
    {
        perror ( "write2" );
    }
    sprintf ( buf, "Content-length: %d\r\n\r\n", (int)strlen(body) );
    if ( write ( fd, buf, strlen(buf) ) != strlen(buf) )
    {
        perror ( "write3" );
    }
    if ( write ( fd, body, strlen(body) ) != strlen ( body ) )
    {
        perror ( "write4" );
    }
}

/*
	Get uri type : regular file or cgi program

	if c_flag defined, and uri starts with c_flag's optarg,
	then this uri should be a regular file; otherwise a cgi. 

	return 1 if it refers to a static file
	return 2 if it refers to a cgi file
*/
int determine_file_type ( char * file )
{
	char file_abs_path [PATH_LEN];
	char cgi_abs_path [PATH_LEN];

	realpath ( file, file_abs_path );
	realpath ( g_cgi_dir_path, cgi_abs_path );

#ifdef DEBUG
	printf ( "[DEBUG] Entering determine_file_type()\n" );
	printf ( "[DEBUG] var file_abs_path: %s\n", file_abs_path );
	printf ( "[DEBUG] var cgi_abs_path: %s\n", cgi_abs_path );
#endif
	if ( c_flag )
	{
		if ( strncmp ( file_abs_path, cgi_abs_path, strlen(cgi_abs_path) ) == 0 )
			return 2;
		else
			return 1;
	}
	else
	{
		return 1;	
	}
}

/*
	Translate an uri into a file path.
*/

void parse_uri ( char * uri, char * filename )
{
	char uri_path [PATH_LEN];
	char file_path [PATH_LEN];
	
	memset ( uri_path, 0x0, sizeof(uri_path) );
	memset ( file_path, 0x0, sizeof(file_path) );

	/* get rid of the first '/' character */
	strcpy ( uri_path, &uri[1] );

	/* request doesn't begins with '~' */
	if ( uri_path[0] != '~' )
	{
		/* combine dir and uri */
		strcpy ( file_path, g_dir_path );
		file_path[strlen(file_path)] = '/';
		//file_path[strlen(file_path)] = '\0';
		strcat ( file_path, uri_path );
	}
	/* request begins with '~' */
	else
	{
		/* if the request begins with a '~', then the following string
		   up to the first slash is translated into that user's sws 
		   directory (ie /home/<user>/sws/).
		*/

		char * p = uri_path + 1;	/* point to first char of user */
		char user [STR_LEN];
		char * q = user;
		char c;

		while ( ((c = (*p)) != '/') && ((c=(*p)) != '\0') )
		{
			*q = c;
			p++;
			q++;
		}
		*(q+1) = '\0';
	    	
		/* construct file path */
		strcat ( file_path, "/home/" );
		strcat ( file_path, user );
		strcat ( file_path, "/sws/" );
		strcat ( file_path, p );	/* contact with the substring after <user> */
	}

	/* return filename */
	strcpy ( filename, file_path );

#ifdef DEBUG
	printf ( "[DEBUG] In the parse_uri() : parsed uri: %s\n", filename );
#endif
}

void get_filetype ( char * filename, char * filetype )
{
    if ( strstr ( filename, ".html" ) )
        strcpy ( filetype, "text/html" );
    else if ( strstr ( filename, ".gif" ) )
        strcpy ( filetype, "image/gif" );
    else if ( strstr ( filename, ".jpg" ) )
        strcpy ( filetype, "image/jpeg" );
    else
        strcpy ( filetype, "text/plain" );
}

void send_http_response ( int fd, char * method, char * body, 
						  char * content_type )
{
    char buf[MAX_LEN];
	char time_str [STR_LEN];

	/* write http response */
    sprintf ( buf, "HTTP/1.0 200 OK\r\n" );
	sprintf ( buf, "%sDate: %s\r\n", buf, 
		get_current_timestamp(time_str, sizeof(time_str)) );
    sprintf ( buf, "%sServer: Simple Web Server\r\n", buf );
    sprintf ( buf, "%sContent-Length: %d\r\n", buf, (int)strlen(body) );
    sprintf ( buf, "%sContent-Type: %s\r\n\r\n", buf, content_type );
	if ( strcmp(method, "HEAD") )
    	sprintf ( buf, "%s%s", buf, body );
    
    if ( write ( fd, buf, strlen(buf) ) != strlen(buf) )
        perror ( "write" );
    else
        printf ( "Http Response has been sent!\n" );
}

void generate_directory_index ( int fd, char * path )
{
#ifdef DEBUG
	printf ( "[DEBUG] Entering generate_directory_index()\n" );
#endif

	char buf [MAX_LEN];
	char body [MAX_LEN];
	char item [MAX_LEN];
	DIR * dp;
	struct dirent * dirp;

	bzero ( buf, sizeof(buf) );
	bzero ( body, sizeof(body) );

	/*
		Build body. 
		read the names of all the files in a directory
	*/
	if ( (dp = opendir (path)) == NULL )
		printf ( "can't open %s\n", path );
	while ( (dirp = readdir(dp)) != NULL )
	{
		if ( dirp->d_name[0] == '.' )
			continue;

		sprintf ( item, "%s\n\r<br/>", dirp->d_name );
		strcat ( body, item );	
	}

	/* 
		Send http response.
	*/

	send_http_response ( fd, "GET", body, "text/html" );
}

/* 
	Read file, generate http response, and send it to the client side. 
	stat(2), open(2), read(2), write(2), close(2)
*/

void handle_regular_file ( int fd, char * method, char * filename, int filesize )
{
    char buf [MAX_LEN];
    char body [MAX_LEN];
    char filetype [MAX_LEN];
    int file_fd;

    bzero ( buf, sizeof(buf) );
    bzero ( body, sizeof(body) );

    get_filetype ( filename, filetype );
    
    /* 
		build body 
	*/

    file_fd = open ( filename, O_RDONLY );
    if ( file_fd < 0 )
    {
        perror ( "open" );
        exit(1);
    }
    if ( read ( file_fd, body, sizeof(body) ) < 0 )
    {
        perror ( "read" );
        exit(1);
    }
	if ( close ( file_fd ) != 0 )
	{
        perror ( "close" );
        exit(1);
	}

    /* 
		send http response 
	*/

	send_http_response ( fd, method, body, filetype );
}

/*
	handle cgi 	
*/

void handle_dynamic_file ( int fd, char * file_name )
{
    char buf[MAX_LEN];
    char * emptylist[] = { NULL };
    pid_t pid;
    int status;

    /* return first part of HTTP response */
    sprintf ( buf, "HTTP/1.0 200 OK\r\n" );
    if ( write ( fd, buf, strlen(buf) ) != strlen(buf) )
    {
        perror ( "write" );
    }
    sprintf ( buf, "Server: Simple Web Server\r\n" );
    if ( write ( fd, buf, strlen(buf) ) != strlen(buf) )
    {
        perror ( "write" );
    }
    
    /* fork - exec executable */
    pid = fork();
    if ( pid < 0 )
    {
        perror ( "fork()" );
        exit(1);
    }
    else if ( pid == 0 )
    {
        /* 
			setup file descriptor ( stdin / stdout )
			makes STDOUT_FILENO be the copy of fd.
		*/

        if ( dup2 ( fd, STDOUT_FILENO ) != STDOUT_FILENO )
        {
            perror ( "dup2()" );
        }
        close ( fd );

        if ( execve ( file_name, emptylist, environ ) < 0 )
        {
            perror ( "execve()" );
        }
    }
    else    /* parent */
    {
        if ( waitpid ( pid, &status, 0 ) != pid )
        {
            perror ( "wait" );
            exit(1);
        }
    }
}

/*
	handle a http request came from client.
*/

void handle_http_request ( int conn_socket_fd )
{
	char buf [MAX_LEN];
	char method [MAX_LEN];
	char request_uri [MAX_LEN];
	char http_version [MAX_LEN];
	char path_name [MAX_LEN];
	int  file_type;
	struct stat sbuf;

	/* reading request line from socket */
	bzero ( buf, sizeof(buf) );
	read_request_line ( conn_socket_fd, buf, sizeof(buf) );

#ifdef DEBUG
	printf ( "[DEBUG] In the handle_http_request(): Request-Line : %s\n", buf );
#endif

	/* 
		fill out log_info structure 
	*/
	strcpy ( g_log_info.first_line_of_request, buf );

	/* parsing the request */
	sscanf ( buf, "%s %s %s", method, request_uri, http_version );
#ifdef DEBUG
	printf ( "[DEBUG] %s\n", method );
	printf ( "[DEBUG] %s\n", request_uri );
	printf ( "[DEBUG] %s\n", http_version );
#endif

	/*
		Validate METHOD, URI, HTTP_VERSION.
	*/

	/* 1. type of request */
	if ( strcmp ( method, "GET" ) && strcmp ( method, "HEAD" ) )
	{
		send_client_error ( conn_socket_fd,
			"Simple Web Server does not implement this method",
			"501",
			"Not Implemented" );

		if ( close ( conn_socket_fd ) != 0 )
			perror ( "close socket" );
		
		return;
	}

	/* 
		2. Determine pathname
	   		a. ~ translation 
			b. Translate relative into absolute pathname
	*/

	parse_uri ( request_uri, path_name );
#ifdef DEBUG
	printf ( "[DEBUG] Path Name : %s\n", path_name );
#endif
		
	if ( stat ( path_name, &sbuf ) < 0 )
	{
		send_client_error ( conn_socket_fd,
					   "Simple Web Server can't find this file",
					   "404",
					   "Not Found" );

		if ( close ( conn_socket_fd ) != 0 )
			perror ( "close socket" );
		
		return;
	}
	else
	{
		/* 
			If the request was for a directory and the directory does 
			not contain a file named "index.html", then sws will generate
			a directory index, listing the contents of the directory
			in alphanumeric order. Files starting with a "." are ignored.
		*/

		/* for a directory */
		if ( S_ISDIR ( sbuf.st_mode ) )
		{
			char index_file_path [PATH_LEN];
			strcpy ( index_file_path, path_name );
			strcat ( index_file_path, "/index.html" );

#ifdef DEBUG
			printf ( "[DEBUG] Index File Path: %s\n", index_file_path );
#endif
			/* no index.html existed, we need to generate Directory Index */
			if ( open ( index_file_path, O_RDONLY ) == -1 )
			{
#ifdef DEBUG
				printf ( "[DEBUG] error before gen dir index: %s\n",
					strerror(errno) );			
#endif
				generate_directory_index ( conn_socket_fd, path_name );
				return;
			}
		}
	}

	/* 3. http version */
	/* ... */	

	/* 
		Generate server status response.
	*/

	file_type = determine_file_type ( path_name );
	if ( file_type == 1 )
	{
		/* handle regular file request */
		
		if ( !(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode) )
		{
			send_client_error ( conn_socket_fd,
				"Simple Web Server can't read the file",
				"403",
				"Forbidden" );
			return;
		}

		handle_regular_file ( conn_socket_fd, method, path_name, sbuf.st_size );
	}
	else if ( file_type == 2 )
	{
		/* handle CGI execution */
		
		/* setup environment */
		/* ..... */

		if ( !(S_ISREG(sbuf.st_mode)) || !(S_IXUSR & sbuf.st_mode) )
		{
			send_client_error ( conn_socket_fd,
				"Simple Web Server can't run the CGI program",
				"403",
				"Forbidden" );
			return;
		}

		handle_dynamic_file ( conn_socket_fd, path_name );
	}
}

/*
	a SIGINT signal handler.
*/

void sig_int ( int signo )
{
	printf ( "\nCaught SIGINT!\n" );
	exit(1);
}

/*
	Write log into file

	Per default, sws does not do any logging. If explicitly enabled via
	the −l flag, sws will log every request in a slight variation of
	Apache’s so-called "common" format: ’%a %t "%r" %>s %b’. That is,
	it will log:
	
		%a The remote IP address.
		%t The time the request was received (in GMT).
		%r The (quoted) first line of the request.
		%>s The status of the request.
		%b Size of the response in bytes. Ie, "Content-Length".
	
	All lines will be appended to the given file unless −d was given,
	in which case all lines will be printed to stdout.
*/

void write_log_info ( char * filename )
{
/* 
	Using system logging API should be implemented later... 
*/
/*
	openlog(filename, LOG_PID|LOG_CONS, LOG_USER);
 	syslog(LOG_INFO, "A different kind of Hello world ... ");
 	closelog();
*/
	
	int log_fd;
	char buf[STR_LEN];

	sprintf ( buf, "%s %s %s %s %s\n",
			  g_log_info.remote_ip_addr,
			  g_log_info.time_request_received,
			  g_log_info.first_line_of_request,
			  g_log_info.status_of_request,
			  g_log_info.size_of_response );

	/* Logging to stdout. */
	if ( d_flag )
	{
		printf ( "%s", buf );
	}
	/* Logging to file. */
	else
	{
		log_fd = open ( filename, O_RDWR | O_CREAT | O_APPEND,
						S_IRUSR	| S_IWUSR );
		if ( log_fd < 0 )
			fprintf ( stderr, "can't open file\n" );

		if ( write ( log_fd, buf, strlen(buf) ) != strlen(buf) )
			fprintf ( stderr, "write error\n" );
		
		if ( close(log_fd) == -1 )
			fprintf ( stderr, "close error\n" );
	}

	/*
		reset log_info structure for the next request
	*/
	memset ( &g_log_info, 0x0, sizeof(g_log_info) );
}


/* 
	program entry
*/

int main ( int argc, char ** argv )
{
	int socket_fd;
	int conn_socket_fd;
	struct sockaddr_in server;
	struct sockaddr_in server_info;
	struct sockaddr_in6 server6;
	struct sockaddr_in6 server6_info;
	struct sockaddr_in remote_ip_addr;
	socklen_t remote_ip_addr_len;
	char remote_ip_addr_buf [STR_LEN];
	int server_len;
	pid_t pid;
	uint16_t port;
	uint32_t ipv4_addr;
	uint8_t ipv6_addr[16];
	int ip_type = -1;
	int listen_queue;

/*
	signal
*/
/*
if ( signal (SIGINT, sig_int) == SIG_ERR )
{
	fprintf ( stderr, "signal error: %s\n", 
		strerror(errno) );
	exit(1);
}
*/
    /* 
        parse command line options 
    */

    parse_cmd_opt ( argc, argv );
    
    /* 
        initialize world...    
    */

	memset ( &g_log_info, 0x0, sizeof(g_log_info) );
    bzero ( ipv6_addr, sizeof(ipv6_addr) );
    bzero ( &server6, sizeof(server6) );
	remote_ip_addr_len = sizeof(remote_ip_addr);

	if ( d_flag )
		listen_queue = 1;
	else
		listen_queue = 5;

    /*
        determine port number
    */

    if ( p_flag )
    {
        port = g_port;
    }
    else
    {
        port = 8080;
    }
    
    /*
        Determine the bind ip type.
    */

    ip_type = determine_ip_type ( g_ip_addr_str );
    if ( ip_type == -1 )
    {
        perror ( "unvalid ip address" );
        exit(1);
    }
   
    /* 
        listen on all IPv4 and IPv6 addresses on this host.
            1. create an IPv6 socket
            2. listen all
    */
    if ( ip_type == 0 )
    {
        socket_fd = socket ( AF_INET6, SOCK_STREAM, 0 );
        if ( socket_fd < 0 )
        {
            perror ( "opening stream socket" );
            exit(1);
        }

        server6.sin6_addr = in6addr_any; 
        server6.sin6_family = AF_INET6;
        server6.sin6_port = htons ( port );
        
        if ( bind ( socket_fd,
                    (struct sockaddr *)&server6, 
                    sizeof(server6) ) )
        {
            perror ( "binding stream socket" );
            exit(1);
        }
        
        /* find out assigned port number and print it out */
        server_len = sizeof ( server6_info );
        if ( getsockname ( socket_fd,
                           (struct sockaddr *)&server6_info,
                           (socklen_t *) &server_len ) )
        {
            perror ( "getting socket name" );
            exit (1);
        }
        printf ( "Socket has port #%d\n", ntohs(server6_info.sin6_port) );
    }
    /* 
        listen on a given IPv4 address
    */
    else if ( ip_type == 1 )
    {
        socket_fd = socket ( AF_INET, SOCK_STREAM, 0 );
        if ( socket_fd < 0 )
        {
            perror ( "opening stream socket" );
            exit(1);
        }

        if ( inet_pton ( AF_INET, g_ip_addr_str, &ipv4_addr ) != 1 )
        {
            perror ( "inet_pton()" );
            exit(1);
        }
        
        server.sin_family = AF_INET;
        server.sin_addr.s_addr =  ipv4_addr;
        server.sin_port = htons ( port );
        
        if ( bind ( socket_fd,
                    (struct sockaddr *)&server, 
                    sizeof(server) ) )
        {
            perror ( "binding stream socket" );
            exit(1);
        }

        /* find out assigned port number and print it out */
        server_len = sizeof ( server_info );
        if ( getsockname ( socket_fd,
                           (struct sockaddr *)&server_info,
                           (socklen_t *) &server_len ) )
        {
            perror ( "getting socket name" );
            exit (1);
        }
        printf ( "Socket has port #%d\n", ntohs(server_info.sin_port) );
    }
    /* 
        listen on a given IPv6 address
    */
    else if ( ip_type == 2 )
    {
        socket_fd = socket ( AF_INET6, SOCK_STREAM, 0 );
        if ( socket_fd < 0 )
        {
            perror ( "opening stream socket" );
            exit(1);
        }

        if ( inet_pton ( AF_INET6, 
                g_ip_addr_str, server6.sin6_addr.s6_addr ) != 1 )
        {
            perror ( "inet_pton()" );
            exit(1);
        }

        server6.sin6_family = AF_INET6;
        server6.sin6_port = htons ( port );
        
        if ( bind ( socket_fd,
                    (struct sockaddr *)&server6, 
                    sizeof(server6) ) )
        {
            perror ( "binding stream socket" );
            exit(1);
        }
        
        /* find out assigned port number and print it out */
        server_len = sizeof ( server6_info );
        if ( getsockname ( socket_fd,
                           (struct sockaddr *)&server6_info,
                           (socklen_t *) &server_len ) )
        {
            perror ( "getting socket name" );
            exit (1);
        }
        printf ( "Socket has port #%d\n", ntohs(server6_info.sin6_port) );
    }

    /* 
        start listening connections
    */
    
    listen ( socket_fd, listen_queue );
    printf ( "Listening...\n" );
    
    /*
        run as a daemon, loop forever
    */
    /* .... */

    while (1)
    {
		printf ( "\nWaiting for a connection...\n" );
            
		/* 
			Accept a connection. 
		*/
        conn_socket_fd = accept ( socket_fd,
			(struct sockaddr *) &remote_ip_addr,
			&remote_ip_addr_len );
		//conn_socket_fd = accept ( socket_fd, 0, 0 );
		if ( conn_socket_fd == -1 )
        {
            perror ( "accept" );
            continue;
        }
        else
            printf ( "\nAccepted...\n" );

		/* fill in log_info structure */
		
		char time_str [STR_LEN];
		strcpy ( g_log_info.time_request_received, 
			get_current_timestamp(time_str, sizeof(time_str)) );
		
		inet_ntop(AF_INET, &remote_ip_addr.sin_addr, 
			remote_ip_addr_buf,
			sizeof(remote_ip_addr_buf));
		strcpy ( g_log_info.remote_ip_addr, remote_ip_addr_buf );
#ifdef DEBUG
		printf ( "[DEBUG] remote ip buf: %s\n", remote_ip_addr_buf );
#endif

        /*
            fork child to handle request
        */
        
        pid = fork();
        if ( pid < 0 )	/* fork() failed */
        {
            perror ( "fork()" );
            exit(1);
        }
        else if ( pid == 0 )    /* child */
        {
			handle_http_request ( conn_socket_fd );

			/* logging */
			write_log_info ( g_log_file );

			/* Remember to terminate the child */
			exit(0);
        }
		else	/* parent */
		{
			/* close the socket */
			if ( close ( conn_socket_fd ) != 0 )
			{
				perror ( "close socket" );
				exit(1);
			}
			else
			{
				printf ( "Close conn_socket_fd\n" );
			}
		}

    } /* end of while(1) */

    /*
        upon SIGHUP re-read configuration, restart
    */
	/* .... */

    /* 
        close accept socket fd
    */
    
    if ( close ( socket_fd ) != 0 )
    {
        perror ( "close socket" );
        exit(1);
    }

    exit(0);
}

