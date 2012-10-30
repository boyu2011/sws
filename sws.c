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

int main ( int argc, char ** argv )
{
    int socket_fd;
    struct sockaddr_in server;
    int server_len;
    int msg_socket;
    char buf[1024];
    int status;
    pid_t pid;
    int read_cnt;

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

    /* .... */


    while (1)
    {

        /*
            accept connection
        */

        msg_socket = accept ( socket_fd, 0, 0 );
        if ( msg_socket == -1 )
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

            /* parsing request */

                /* valid syntax? */

                /* type of request */

                /* determine pathname ( ~ translation /
                   trslate relative into absolute pathname ) */

            /* generate server status response */

            /* handle request */

                /* handle regular file request */

        
                    /* stat(2), open(2), read(2), write(2), close(2) */

                    /* terminate connection, exit child handler */

                /* handle CGI execution */

                    /* setup environment */

                    /* setup file descriptor ( stdin / stdout ) */

                    /* fork - exec executable */

        }

        /* parent !!!need more considerable!!! */
        if ( pid != 0 )
        {
            if ( waitpid ( pid, &status, 0 ) != pid )
            {
                perror ( "wait.." );
                exit(1);
            }
        }

        /* close socket */
        if ( close ( msg_socket ) != 0 )
        {
            perror ( "close socket" );
            exit(1);
        }
    }

    /*
        upon SIGHUP re-read configuration, restart
    */



    exit(0);
}
