/*
    sws.c -- a simple web server

    Developer : Bo Yu (boyu2011@gmail.com)
*/

#include <stdio.h>
#include <stdlib.h>
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

#define DEBUG

/* buggy: deal with large file */
#define MAX_LEN 99999

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
char g_dir_path [MAX_LEN];		 /* serve content from given directory */

/*
    functions
*/

void usage()
{
    printf ( "sws -- a simple web server\n" );
    printf ( "Usage: sws [-dh] [-c dir] [-i address] [-l file] [-p port] [-s dir -k key] dir\n" );
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
                break;

            case 'i':
                i_flag = 1;
                /* identity the address is ipv4 or ipv6 ... */
                strcpy ( g_ip_addr_str, optarg );
                printf ( "## g_ip_addr_str : %s\n", g_ip_addr_str );
                break;

            case 'l':
                l_flag = 1;
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
		printf ( "[DEBUG] dir argument : %s\n", *argv );
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

int determine_ip ( char * ip_addr )
{
    uint32_t ipv4_dest;
    uint8_t ipv6_dest[16];
    int ret;
   
    if ( !i_flag )
    {
        return 0;   /* listen on all IPv4&IPv6 addresses on this host */
    }

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
	return 1 if it refers to a static file
	return 2 if it refers to a cgi file
*/
int determine_uri_type ( char * uri )
{
	if ( ! strstr(uri, "cgi-bin") )
	{
		return 1;
	}
	else
	{
		return 2;
	}
}

/*
*/

void parse_uri ( char * uri, char * filename )
{
	/* get rid of the first '/' character */
	strcpy ( filename, &uri[1] );

	/* TO DO ... */
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

/* 
	Read file, generate http response, and send it to the client side. 
	stat(2), open(2), read(2), write(2), close(2)
*/

void handle_regular_file ( int fd, char * filename, int filesize )
{
    char buf [MAX_LEN];
    char body [MAX_LEN];
    char filetype [MAX_LEN];
    int file_fd;

    bzero ( buf, sizeof(buf) );
    bzero ( body, sizeof(body) );

    get_filetype ( filename, filetype );
    
    /* build body */
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

    /* write http response */
    sprintf ( buf, "HTTP/1.0 200 OK\r\n" );
    sprintf ( buf, "%sServer: Simple Web Server\r\n", buf );
    sprintf ( buf, "%sContent-Length: %d\r\n", buf, filesize );
    sprintf ( buf, "%sContent-Type: %s\r\n\r\n", buf, filetype );
    sprintf ( buf, "%s%s", buf, body );
    
    if ( write ( fd, buf, strlen(buf) ) != strlen(buf) )
    {
        perror ( "write" );
    }
    else
    {
        printf ( "Static file %s has been sent!\n", filename );
    }
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
        /* setup file descriptor ( stdin / stdout ) */
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
	handle a http request from client.
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
	printf ( "[DEBUG] Read Request-Line : %s\n", buf );
#endif

	/* parsing the request */
	sscanf ( buf, "%s %s %s", method, request_uri, http_version );
	
	/*
		valid syntax?
	*/

	/* 1. type of request */

	if ( strcmp ( method, "GET" ) )
	{
		send_client_error ( conn_socket_fd,
			"Simple Web Server does not implement this method",
			"501",
			"Not Implemented" );

		if ( close ( conn_socket_fd ) != 0 )
		{
			perror ( "close socket" );
			exit(1);
		}
		exit(1);
	}

	/* 2. Determine pathname
	   ( ~ translation; Translate relative into absolute pathname ) */

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
		{
			perror ( "close socket" );
			exit(1);
		}
		exit(1);
	}

	/* 3. http version */
		

	/* 
		Generate server status response
	*/

	file_type = determine_uri_type ( request_uri );
	
	if ( file_type == 1 )
	{
		/* handle regular file request */
		
		if ( !(S_ISREG(sbuf.st_mode)) || 
			 !(S_IRUSR & sbuf.st_mode) )
		{
			send_client_error ( conn_socket_fd,
				"Simple Web Server can't read the file",
				"403",
				"Forbidden" );
			exit(1);
		}

		handle_regular_file ( conn_socket_fd, path_name, sbuf.st_size );
	}
	else if ( file_type == 2 )
	{
		/* handle CGI execution */
		
		/* setup environment */
		/* ..... */

		if ( !(S_ISREG(sbuf.st_mode)) || 
			 !(S_IXUSR & sbuf.st_mode) )
		{
			send_client_error ( conn_socket_fd,
				"Simple Web Server can't run the CGI program",
				"403",
				"Forbidden" );
			exit(1);
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
	int server_len;
	pid_t pid;
	uint16_t port;
	uint32_t ipv4_addr;
	uint8_t ipv6_addr[16];
	int ip_type = -1;

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

    bzero ( ipv6_addr, sizeof(ipv6_addr) );
    bzero ( &server6, sizeof(server6) );

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

    ip_type = determine_ip ( g_ip_addr_str );
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
    
    listen ( socket_fd, 5 );
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

        conn_socket_fd = accept ( socket_fd, 0, 0 );
        if ( conn_socket_fd == -1 )
        {
            perror ( "accept" );
            continue;
        }
        else
        {
            printf ( "\nAccepted...\n" );
        }

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
