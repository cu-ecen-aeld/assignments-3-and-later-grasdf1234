/*
** server.c -- a stream socket server demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <stdbool.h>

#define PORT "9000" // the port users will be connecting to

#define BACKLOG 10 // how many pending connections queue will hold

int sockfd, new_fd; // listen on sock_fd, new connection on new_fd
FILE *file;
char datadir[] = "/var/tmp/aesdsocketdata";

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;

    errno = saved_errno;
}

void handle_signal(int signal)
{
    // Handle SIGINT and SIGTERM signals
    printf("\nReceived signal %d, closing resources...\n", signal);
    syslog(LOG_ERR, "Caught signal, exiting");
    if (file != NULL)
    {
        fclose(file);
    }
    if (sockfd != -1)
    {
        close(sockfd);
    }
    remove(datadir);
    exit(EXIT_SUCCESS);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
    openlog("aesdsocket", 0, LOG_USER);

    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    // Setup signal handling
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1)
        {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1)
        {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)
    {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }
    bool daemon = false;
    if (argc == 2 && (strcmp(argv[1], "-d") == 0))
    {
        printf("daeeeeeemon!");
        daemon = true;
    }
 
     if (!daemon || !fork())
    { // child
        // close(sockfd);

        if (listen(sockfd, BACKLOG) == -1)
        {
            perror("listen");
            exit(1);
        }

        sa.sa_handler = sigchld_handler; // reap all dead processes
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL) == -1)
        {
            perror("sigaction");
            exit(1);
        }

        file = fopen(datadir, "w+");

        if (file == NULL)
        {
            printf("Error!");
            syslog(LOG_ERR, "Error opening file!");
            closelog();
            exit(1);
        }

        printf("server: waiting for connections...\n");

        while (1)
        { // main accept() loop
            sin_size = sizeof their_addr;
            new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
            if (new_fd == -1)
            {
                perror("accept");
                continue;
            }

            inet_ntop(their_addr.ss_family,
                      get_in_addr((struct sockaddr *)&their_addr),
                      s, sizeof s);
            syslog(LOG_DEBUG, "Accepted connection from %s", s);

            printf("server: got connection from %s\n", s);

#define BUFFERSIZE 500000
            char socketbuf[BUFFERSIZE];
            char filereadbuf[BUFFERSIZE];
            // nt rec = recv(sockfd, buf, BUFFER)
            int bytes_received;
            int bytes_read;

            while ((bytes_received = recv(new_fd, socketbuf, BUFFERSIZE - 1, 0)) > 0)
            {

                socketbuf[bytes_received] = '\0'; // Null-terminate the received data
                //printf("Received: %s\n", socketbuf);

                /* code */
                syslog(LOG_DEBUG, "Writing %s to %s", socketbuf, datadir);
                fprintf(file, "%s", socketbuf);
                fflush(file);
                rewind(file);
                while ((bytes_read = fread(filereadbuf, 1, BUFFERSIZE, file)) > 0)
                {
                    syslog(LOG_DEBUG, "read: %i", bytes_read);

                    int sent;
                    if ((sent = send(new_fd, filereadbuf, bytes_read, 0)) == -1)
                    {
                        perror("Send failed");
                        close(new_fd);
                        fclose(file);
                        exit(EXIT_FAILURE);
                    }
                    else
                    {
                        syslog(LOG_DEBUG, "sent: %i", sent);
                    }
                }
            }

            syslog(LOG_DEBUG, "Closed connection from %s", s);

            close(new_fd);
        }
    } // end child

    // close(new_fd); // parent doesn't need this
    // fclose(file);
    // closelog();

    return 0;
}