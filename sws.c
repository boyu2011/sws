/*
    sws.c -- a simple web server

    Developer : Bo Yu (boyu2011@gmail.com)
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/wait.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/stat.h>

#define DEBUG
#define MAX_LEN 1024

/*
    read first line ( request line ) from http request
*/

ssize_t readline ( int fd, void * userbuf, size_t maxlen )
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
void client_error ( int fd, char * error_cause, char * error_number,
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
    if ( write ( fd, body, strlen(body) ) )
    {
        perror ( "write4" );
    }
}

void parse_uri ( char * uri, char * filename )
{
    /* remove the first char '/' */
    strcpy ( filename, &uri[1] );
}


void handle_regular_file ( int fd, char * filename )
{
    char buf [MAX_LEN];
    char body [MAX_LEN];
    int file_fd;

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

    /* write http response */
    sprintf ( buf, "HTTP/1.0 200 OK\r\n" );
    sprintf ( buf, "%sServer: Simple Web Server\r\n", buf );
    sprintf ( buf, "%sContent-length: 20\r\n", buf );
    sprintf ( buf, "%sContent-type: text/html\r\n\r\n", buf );
    /*
    sprintf ( buf, "%s<html>this is an amazing time!!!</html>\r\n", buf );
    */
    sprintf ( buf, "%s%s", buf, body );
    
    if ( write ( fd, buf, strlen(buf) ) != strlen(buf) )
    {
        perror ( "write" );
    }
    else
    {
        printf ( "file has been sent!!\n" );
    }
}

int main ( int argc, char ** argv )
{
    int socket_fd;
    int conn_socket_fd;
    struct sockaddr_in server;
    int server_len;
    char buf[MAX_LEN];
    char method [MAX_LEN];
    char request_uri [MAX_LEN];
    char http_version [MAX_LEN];
    int status;
    pid_t pid;
    char file_name[MAX_LEN];
    struct stat sbuf;

    /* 
        parse command line options 
    */

    /* 
        initialize world...    
    */

    /* 
        open socket 
    */

    /* create socket */
    
    socket_fd = socket ( AF_INET, SOCK_STREAM, 0 );
    if ( socket_fd < 0 )
    {
        perror ( "opening stream socket" );
        exit(1);
    }

    /* name socket */
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = 0;

    if ( bind ( socket_fd,
                (struct sockaddr *)&server, 
                sizeof(server) ) )
    {
        perror ( "binding stream socket" );
        exit(1);
    }

    /* find out assigned port number and print it out */
    server_len = sizeof ( server );
    if ( getsockname ( socket_fd,
                       (struct sockaddr *)&server,
                       (socklen_t *) &server_len ) )
    {
        perror ( "getting socket name" );
        exit (1);
    }
    printf ( "Socket has port #%d\n", ntohs(server.sin_port) );

    /* start listening connections */
    listen ( socket_fd, 5 );
    printf ( "Listening...\n" );
    
    /*
        run as a daemon, loop forever
    */


    while (1)
    {
        /*
            accept connection
        */

        conn_socket_fd = accept ( socket_fd, 0, 0 );
        if ( conn_socket_fd == -1 )
        {
            perror ( "accept" );
            continue;
        }
        else
        {
            printf ( "Accepted...\n" );
        }

        /*
            fork child to handle request
        */
        
        pid = fork();
        if ( pid < 0 )
        {
            perror ( "fork()" );
            exit(1);
        }
        else if ( pid == 0 )
        {
            /* reading request from socket */

            bzero ( buf, sizeof(buf) );
            readline ( conn_socket_fd, buf, sizeof(buf) );
#ifdef DEBUG
            printf ( "[DEBUG INFO] Request-Line : %s\n", buf );
#endif

/*
            do {
                bzero ( buf, sizeof(buf) );
                if ( ( read_cnt = read ( msg_socket, buf, 1024 ) ) < 0 )
                {
                    perror ( "reading stream message" );
                }
                
                if ( read_cnt == 0 )
                {
                    printf ( "Ending connection\n" );
                }
                else
                {
                    printf ( "-->%s\n", buf );
                }
        
            }while ( read_cnt != 0 );
            printf ( "out of while ( read_cnt!=0 )\n" );
*/

            /* 
                parsing request
            */
            
            sscanf ( buf, "%s %s %s", method, request_uri, http_version );

            /* valid syntax? */

            /* type of request */
            if ( strcmp ( method, "GET" ) )
            {
                client_error ( conn_socket_fd,
                               "Simple Web Server does not implement this method",
                               "501",
                               "Not Implemented" );

                if ( close ( conn_socket_fd ) != 0 )
                {
                    perror ( "close socket" );
                    exit(1);
                }
                continue;
            }

            /* determine pathname ( ~ translation /
               trslate relative into absolute pathname ) */
            parse_uri ( request_uri, file_name );
            if ( stat ( file_name, &sbuf ) < 0 )
            {
                client_error ( conn_socket_fd,
                               "Simple Web Server can't find this file",
                               "404",
                               "Not Found" );

                if ( close ( conn_socket_fd ) != 0 )
                {
                    perror ( "close socket" );
                    exit(1);
                }
                continue;
            }

            /* 
                generate server status response
            */

            /* handle request */

                /* handle regular file request */
        
                    /* stat(2), open(2), read(2), write(2), close(2) */

                    handle_regular_file ( conn_socket_fd, file_name ); 

                    /* terminate connection, exit child handler */

                /* handle CGI execution */

                    /* setup environment */

                    /* setup file descriptor ( stdin / stdout ) */

                    /* fork - exec executable */

        }

        /* parent !!!need more consideration!!! */
        if ( pid != 0 )
        {
            if ( waitpid ( pid, &status, 0 ) != pid )
            {
                perror ( "wait" );
                exit(1);
            }
        }

        /* close socket */
        if ( close ( conn_socket_fd ) != 0 )
        {
            perror ( "close socket" );
            exit(1);
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
