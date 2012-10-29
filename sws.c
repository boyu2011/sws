/*
    sws.c -- a simple web server

    Developer : Bo Yu (boyu2011@gmail.com)
*/

#include <stdio.h>
#include <stdlib.h>

int main ( int argc, char ** argv )
{

    /* 
        parse command line options 
    */

    /* 
        initialize world...    
    */

    /* 
        open socket 
    */

    /*
        run as a daemon, loop forever
    */

    /*
        accept connection
    */

    /*
        fork child to handle request
    */

        /* reading request from socket */

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

    /*
        upon SIGHUP re-read configuration, restart
    */


    exit(0);
}
