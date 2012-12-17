/*
    sws.c -- a simple web server

	sws is a very simple web server. It behaves quite like you would
	expect from any regular web server, in that it binds to a given
	port on the given address and waits for incoming HTTP/1.0 requests.
	It serves content from the given directory. That is, any requests 
	from documents is resolved relative to this directory (the document
	root).

    Developer : Bo Yu (boyu2011@gmail.com)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define DEBUG

/* buggy: how to solve large file issue */
#define MAX_LEN 9999
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
	int status_of_request;
	int size_of_response;
};

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
    Global Variables
*/

int  g_port = 0;     			 /* port number */
char g_ip_addr_str [MAX_LEN];    /* ip address got from -i */
char g_dir_path [PATH_LEN];		 /* serve content from given directory */
char g_cgi_dir_path [PATH_LEN];	 /* allow execution of CGIs from
									the given directory */
char g_log_file [PATH_LEN];		 /* log all requests to the given file */
int  g_is_cgi_request = 0;		 /* indicate that the request is a cgi request */

struct log_info g_log_info;

/*
    Function Implementations.
*/

/*
	Usage Information.
*/

void usage()
{
    printf ( "sws -- a simple web server\n" );
    printf ( "Usage: sws [-dh] [-c dir] [-i address] [-l file] " );
	printf ( "[-p port] [-s dir -k key] dir\n" );
}

/*
	Get current time.
*/

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
    Get IP type ( ipv4/ipv6 )
	
		return 0 means listen on all Ipv4 and Ipv6 addresses 
		on this host
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
        return 0;   /* listen on all IPv4&IPv6 addresses */
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

	See RFC 1945 5.1
		Request-Line = Method SP Request-URI SP HTTP-Version CRLF
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
            if ( c == '\015' )	/* CR */
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
	
	*(bufp-1) = '\0';		/* replace CR with '\0' */
    *bufp = '\0';
    return n;
}

/* 
	Read a line from file descriptor.
*/

ssize_t read_line ( int fd, void * userbuf, size_t maxlen )
{
	int n, read_cnt;
	char c;
    char * bufp = userbuf;

    for ( n = 0; n < maxlen; n++ )
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
            if ( n == 0 )
                return 0;   /* EndOfFile, no data read */
            else
                break;      /* EndOfFile, data was read */
        }
        else
        {
            return -1;      /* error */
        }
    }
	
	*(bufp) = '\0';
    return n;
}

/*
    Send an error message to client side.
*/

void send_client_error ( int fd, char * error_cause, 
	char * error_number, char * error_reason_phrase )
{
    char buf [MAX_LEN];
    char body [MAX_LEN];
	char time_str [STR_LEN];

    /* Build the HTTP response body */
    sprintf ( body, "<html><title>Error</title>\r\n" );
    sprintf ( body, "%s%s: %s\r\n", body, error_number, 
		error_reason_phrase );
    sprintf ( body, "%s<br>%s\r\n", body, error_cause );
    sprintf ( body, "%s<hr>Simple Web Server\r\n", body );

    /* Write the HTTP response to the client. */
	/* 1. Status Code */
    sprintf ( buf, "HTTP/1.0 %s %s\r\n", error_number, 
		error_reason_phrase );
    if ( write ( fd, buf, strlen(buf) ) != strlen (buf) )
    {
        perror ( "write1" );
    }
	/* 2. Headers */
	/* 2.1 Date */
	sprintf ( buf, "Date: %s\r\n", 
			  get_current_timestamp(time_str, sizeof(time_str)));
    if ( write ( fd, buf, strlen(buf) ) != strlen (buf) )
    {
        perror ( "write2" );
    }
	/* 2.2 Server */
	sprintf ( buf, "Server: Simple Web Server\r\n" );
    if ( write ( fd, buf, strlen(buf) ) != strlen (buf) )
    {
        perror ( "write2" );
    }
	/* 2.3 Last-Modified (Ignored) */
	/* 2.4 Content-Type */
    sprintf ( buf, "Content-type: text/html\r\n" );
    if ( write ( fd, buf, strlen(buf) ) != strlen (buf) )
    {
        perror ( "write2" );
    }
	/* 2.5 Content-Length */
    sprintf ( buf, "Content-length: %d\r\n\r\n", (int)strlen(body) );
    if ( write ( fd, buf, strlen(buf) ) != strlen(buf) )
    {
        perror ( "write3" );
    }
	/* 3. Body */
    if ( write ( fd, body, strlen(body) ) != strlen ( body ) )
    {
        perror ( "write4" );
    }

	/* Assigned request status into g_log_info. */
	g_log_info.status_of_request = atoi( error_number );
	/* Assigned response size into g_log_info. */
	g_log_info.size_of_response = (int) strlen(body); 
}

/*
	Parse URI into local file path.
*/

void parse_uri ( char * uri, char * filename )
{
	char uri_tmp [PATH_LEN];
	char file_tmp [PATH_LEN];

	memset ( uri_tmp, 0x0, sizeof(uri_tmp) );
	memset ( file_tmp, 0x0, sizeof(file_tmp) );

	/* get rid of the first character '/' of uri */
	strcpy ( uri_tmp, &uri[1] );

	/* if uri doesn't start with '~' */
	if ( uri_tmp[0] != '~' )
	{
		/* if uri begins with cgi-bin, it means this request is a cgi request */
		if ( strncmp ( uri_tmp, "cgi-bin", 7 ) == 0 )
		{
			/* if -c existed */
			if ( c_flag )
			{
				g_is_cgi_request = 1;
				
				/* combine cgi-dir and uri substract cgi-bin */
				strcpy ( file_tmp, g_cgi_dir_path );
				file_tmp[strlen(file_tmp)] = '/';
				strcat ( file_tmp, &uri_tmp[7] );
			}
			/* else combine dir and uri */
			else
			{
				strcpy ( file_tmp, g_dir_path );
				file_tmp[strlen(file_tmp)] = '/';
				strcat ( file_tmp, uri_tmp );
			}
		}
		/* else it means it is a regular file request */
		else
		{
			/* combine dir and uri */
			strcpy ( file_tmp, g_dir_path );
			file_tmp[strlen(file_tmp)] = '/';
			strcat ( file_tmp, uri_tmp );
		}
	}
	/* else uri starts with '~' */
	else
	{
		/* if the request begins with a '~', then the following string
		   up to the first slash is translated into that user's sws 
		   directory (ie /home/<user>/sws/).
		*/

		char * p = uri_tmp + 1;	/* point to first char of user */
		char user [STR_LEN];
		memset ( user, 0x0, sizeof(user) );
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
		strcat ( file_tmp, "/home/" );
		strcat ( file_tmp, user );
		strcat ( file_tmp, "/sws/" );
		strcat ( file_tmp, p );	/* contact with the uri's substring after <user> */
	}

	/* return filename */
	strcpy ( filename, file_tmp );	
}

/*
	Determine file type based on suffix.
	(or, optionally, the correct content-type for the file in question
	 as determined via magic(5) patterns.)
*/

void get_filetype ( char * filename, char * filetype )
{
    if ( strstr ( filename, ".gif" ) )
        strcpy ( filetype, "image/gif" );
    else if ( strstr ( filename, ".jpg" ) )
        strcpy ( filetype, "image/jpeg" );
    else
        strcpy ( filetype, "text/html" );
}

/*
	Send data (in the body) via HTTP.
*/

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
#ifdef DEBUG
    else
        printf ( "Http Response has been sent!\n" );
#endif

	/* Assigned request status into g_log_info. */
	g_log_info.status_of_request = 200;
	/* Assigned response size into g_log_info. */
	g_log_info.size_of_response = (int) strlen(body); 
}

/*
	List the contents of the directory, and send via HTTP.
*/

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

void handle_regular_file ( int fd, char * method, char * filename,
						   int filesize )
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
	Handle CGI GET Request.	
*/

void handle_dynamic_file ( int fd, char * file_name )
{
    char buf[MAX_LEN];
    char * emptylist[] = { NULL };
    pid_t pid;
    int status;
	char time_str [STR_LEN];

    /* return first part of HTTP response */
    sprintf ( buf, "HTTP/1.0 200 OK\r\n" );
    if ( write ( fd, buf, strlen(buf) ) != strlen(buf) )
    {
        perror ( "write" );
    }
	sprintf ( buf, "%sDate: %s\r\n", buf, 
		get_current_timestamp(time_str, sizeof(time_str)) );
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
	
			Close STDOUT_FILENO, make STDOUT_FILENO the copy of fd.
			0
			1-----|
			2	  |
			fd---------
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
	Handle POST request.
*/

void handle_post_request ( int socket, char * path_name )
{
	char buf[1024];
	int fd[2];
	pid_t pid;
	int numchars = 1;
	int content_length = -1;
	char post_para [1024];
	char length_env [1024];

	/* 
		get Content-Length
	*/
	/* get '/n' from request line */
	numchars = read_line ( socket, buf, sizeof(buf) );
	/* get Content-Length: */
	numchars = read_line ( socket, buf, sizeof(buf) );
#ifdef DEBUG
	printf ( "[DEBUG] buf: %s numchars: %d\n", buf, numchars );
#endif
	if ( strstr ( buf, "Content-Length:" ) != NULL )
	{
		content_length = atoi(&buf[15]);
#ifdef DEBUG
		printf ( "[DEBUG] content_length:\n%d\n", content_length );
#endif
	}
	if ( content_length == -1 )
	{
		send_client_error ( socket,
			"Simple Web Server Internal Error",
			"500",
			"Internal Server Error" );
		return;
	}

	/* 
		get POST parameters 
	*/
	numchars = read_line ( socket, 
		post_para, sizeof(post_para) );
#ifdef DEBUG
	printf ( "[DEBUG] parameters: %s\n", post_para );
#endif

	sprintf(buf, "HTTP/1.0 200 OK\r\n");
	write( socket, buf, strlen(buf) );

	if ( pipe ( fd ) < 0 )
	{
		perror ( "pipe()" );
		return;
	}

	/* 
		Create a new process: the parent send post parameter to
		child, the child read the parameter by a cgi program.
	*/
	pid = fork();
	if ( pid < 0 )
	{
		perror ( "fork()" );
		return;
	}
	else if ( pid == 0 )	/* child */
	{
		/* read from fd[0] */
		dup2 ( fd[0], STDIN_FILENO );
		/* write to socket */
		dup2 ( socket, STDOUT_FILENO );

		/* set environment var */
		/* buggy: conent_length can not large than 10?? */
		sprintf ( length_env, "CONTENT_LENGTH=%d",
			content_length );
		putenv ( length_env );	

		/* execute program */
		execl ( path_name, path_name, NULL );

		fprintf ( stderr, "execl error for %s\n", path_name );
		exit(1);	
	}
	else	/* parent */
	{
		/* write post parameter to child */
		write ( fd[1], post_para, strlen(post_para) );

		close ( fd[1] );

		if ( waitpid(pid, NULL, 0) < 0 )
		{
			perror ( "waitpid error" );
			return;
		}
	}
}

/*
	Handle HTTP request (GET / HEAD / CGI / POST)
*/

void handle_http_request ( int conn_socket_fd )
{
	char buf [MAX_LEN];
	char method [MAX_LEN];
	char request_uri [MAX_LEN];
	char http_version [MAX_LEN];
	char path_name [MAX_LEN];
	struct stat sbuf;

	/* reading request line from socket */
	bzero ( buf, sizeof(buf) );
	read_request_line ( conn_socket_fd, buf, sizeof(buf) );
#ifdef DEBUG
	printf ( "[DEBUG] handle_http_request(): Request-Line : %s\n", 
		buf );
#endif

	/* Assigned requestline field of g_log_info structure. */
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
		If any validation failed, function will return immediately.
	*/

	/* 1. Only GET , POST and HEAD requests are supported. */
	if ( strcmp ( method, "GET" )  &&
		 strcmp ( method, "HEAD" ) &&
		 strcmp ( method, "POST" ) )
	{
		send_client_error ( conn_socket_fd,
			"Simple Web Server does not implement this method",
			"501",
			"Not Implemented1" );

		if ( close ( conn_socket_fd ) != 0 )
			perror ( "close socket" );
		
		return;
	}

	/* 
		2. Determine URI.
	*/

	/*
		2.1 Parse URI that translate URI to file name.
		a. ~ translation 
		b. Translate relative into absolute pathname
	*/
	parse_uri ( request_uri, path_name );
#ifdef DEBUG
	printf ( "[DEBUG] After parse_uri(): file path : %s\n", 
		path_name );
#endif
	
	/*  2.2 File should exist */
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
	/* File does not exist. */
	else
	{
		/* 
			If the request was for a directory and the directory does 
			not contain a file named "index.html", then sws will
			generate a directory index, listing the contents of the
			directory in alphanumeric order. Files starting with a
			"." are ignored.
		*/

		/* For a directory */
		if ( S_ISDIR ( sbuf.st_mode ) )
		{
			char index_file_path [PATH_LEN];
			strcpy ( index_file_path, path_name );
			strcat ( index_file_path, "/index.html" );
#ifdef DEBUG
			printf ( "[DEBUG] Index File Path: %s\n", 
				index_file_path );
#endif
			/* Since there is no index.html existed, sws will
			   generate Directory Index */
			if ( open ( index_file_path, O_RDONLY ) == -1 )
			{
#ifdef DEBUG
				printf ( "[DEBUG] error before gen dir index: %s\n",
					strerror(errno) );			
#endif
				generate_directory_index ( conn_socket_fd, path_name );
				return;
			}
			/* There is an index.html file, so return it as response */
			else
			{
				struct stat index_sbuf;

				if ( stat ( index_file_path, & index_sbuf ) < 0 )
				{
					send_client_error ( conn_socket_fd,
						"Simple Web Server can't find this file",
						"404",
						"Not Found" );

					if ( close ( conn_socket_fd ) != 0 )
						perror ( "close socket" );

					return;
				}
				
				if ( !(S_ISREG(index_sbuf.st_mode)) ||
					 !(S_IRUSR & index_sbuf.st_mode) )
				{
					send_client_error ( conn_socket_fd,
						"Simple Web Server can't read the file",
						"403",
						"Forbidden" );
					
					return;
				}

				handle_regular_file ( conn_socket_fd, "GET", 
					index_file_path, index_sbuf.st_size );

				return;
			}
		}
	}

	/* 
		3. Validate Http Version. 
	*/
	
	if ( strcmp ( http_version, "HTTP/1.0" ) != 0 )
	{
		send_client_error ( conn_socket_fd,
			"Simple Web Server does not support this Http Version",
			"501",
			"Not Implemented2" );

		if ( close ( conn_socket_fd ) != 0 )
			perror ( "close socket" );
		
		return;
	}

	/* 
		Generate HTTP Response.
	*/

	/* Regular GET or HEAD request. */
	if ( ! g_is_cgi_request )
	{
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
	/* GET CGI or POST request. */
	else
	{
		if ( !(S_ISREG(sbuf.st_mode)) || !(S_IXUSR & sbuf.st_mode) )
		{
			send_client_error ( conn_socket_fd,
				"Simple Web Server can't run the CGI program",
				"403",
				"Forbidden" );
			return;
		}

		if ( strcmp ( method, "POST" ) == 0 )
			handle_post_request ( conn_socket_fd, path_name );	
		else
			handle_dynamic_file ( conn_socket_fd, path_name );
	}
}

/*
	a SIGINT signal handler.
*/

void sig_int ( int signo )
{
	exit(1);
}

/*
	Write log information into a given file.

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
	int log_fd;
	char buf[STR_LEN];

	sprintf ( buf, "%s  %s  %s  %d  %d\n",
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
		if ( l_flag )
		{
			log_fd = open ( filename, O_RDWR | O_CREAT | O_APPEND,
							S_IRUSR	| S_IWUSR );
			if ( log_fd < 0 )
				fprintf ( stderr, "write_log_info(): can't open file\n" );

			if ( write ( log_fd, buf, strlen(buf) ) != strlen(buf) )
				fprintf ( stderr, "write_log_info(): write error\n" );
			
			if ( close(log_fd) == -1 )
				fprintf ( stderr, "write_log_info(): close error\n" );
		}
	}

	/*
		Reset log_info structure for the next request.
	*/
	memset ( &g_log_info, 0x0, sizeof(g_log_info) );
}

/* 
	program entry.
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
		Set signal handler.
	*/

	if ( signal (SIGINT, sig_int) == SIG_ERR )
	{
		fprintf ( stderr, "signal error: %s\n", 
			strerror(errno) );
		exit(1);
	}

    /* 
    	Parse command line options. 
    */

    parse_cmd_opt ( argc, argv );
    
    /* 
        Initialize world...    
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
        Determine port number.
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
            Step 1. create an IPv6 socket
            Setp 2. listen all
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
#ifdef DEBUG
        printf ( "[DEBUG] Socket has port #%d\n", 
			ntohs(server6_info.sin6_port) );
#endif    
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
#ifdef DEBUG
        printf ( "[DEBUG] Socket has port #%d\n", 
			ntohs(server_info.sin_port) );
#endif    
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
#ifdef DEBUG
        printf ( "[DEBUG] Socket has port #%d\n", 
			ntohs(server6_info.sin6_port) );
#endif
	}

    /* 
        start listening connections
    */
    
    listen ( socket_fd, listen_queue );
#ifdef DEBUG
    printf ( "[DEBUG] Listening...\n" );
#endif

    /*
        run as a daemon, loop forever
    */
    
	if ( ! d_flag )
	{
		if ( daemon ( 1, 1 ) < 0 )
		{
			perror ( "daemon" );
			exit ( 1 );
		}
	}

    while (1)
    {
		/* init cgi request var */
		g_is_cgi_request = 0;

#ifdef DEBUG
		printf ( "\n[DEBUG] Waiting for a connection...\n" );
#endif
		/* 
			Accept a connection. 
		*/
        conn_socket_fd = accept ( socket_fd,
								  (struct sockaddr *) &remote_ip_addr,
								  &remote_ip_addr_len );
		if ( conn_socket_fd == -1 )
        {
            perror ( "accept" );
            continue;
        }
#ifdef DEBUG
        else
            printf ( "\n[DEBUG] Accepted.\n" );
#endif

		/* 
			Fill in log_info structure 
		*/
		/* timestamp */	
		char time_str [STR_LEN];
		strcpy ( g_log_info.time_request_received, 
			get_current_timestamp(time_str, sizeof(time_str)) );
		/* remote ip */
		inet_ntop(AF_INET, &remote_ip_addr.sin_addr, 
			remote_ip_addr_buf,
			sizeof(remote_ip_addr_buf));
		strcpy ( g_log_info.remote_ip_addr, remote_ip_addr_buf );

        /*
            Fork child to handle request
        */
        
        pid = fork();
        if ( pid < 0 )	/* fork() failed */
        {
            perror ( "fork()" );
            exit(1);
        }
        else if ( pid == 0 )    /* child */
        {
			/* Handle Http Request. */
			handle_http_request ( conn_socket_fd );

			/* Do logging */
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
				printf ( "[DEBUG] conn_socket_fd has been closed.\n" );
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
	
	/* Program shutdown successfully. */
	exit(0);
}
