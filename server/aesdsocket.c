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
#include <pthread.h>
#include <time.h>
#include "queue.h"

#define PORT "9000" // the port users will be connecting to

#define BACKLOG 10 // how many pending connections queue will hold
#define BUFFERSIZE 500000
size_t bufferSize = BUFFERSIZE;

// SLIST.
typedef struct slist_data_s slist_data_t;
struct slist_data_s
{
    pthread_t thread_id;
    bool done;
    int connection_fd;
    SLIST_ENTRY(slist_data_s)
    entries;
};

int sockfd, new_fd; // listen on sock_fd, new connection on new_fd
FILE *file;
char datadir[] = "/var/tmp/aesdsocketdata";

pthread_mutex_t counter_mutex;

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
    printf("\nReceived signal %d\n", signal);

    if (signal == SIGINT || signal == SIGTERM)
    {
        printf("\n, closing resources...\n");

        // syslog(LOG_ERR, "Caught signal, exiting");
        if (file != NULL)
        {
            fclose(file);
        }
        if (sockfd != -1)
        {
            close(sockfd);
        }
        remove(datadir);

        // if (socketbuf != NULL)
        //     free(socketbuf);
        // if (filereadbuf != NULL)
        //     free(filereadbuf);

        exit(EXIT_SUCCESS);
    }
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

void *thread_connection(void *arg)
{
    slist_data_t *this_datap = (slist_data_t *)arg;

    char *socketbuf = (char *)malloc(bufferSize + sizeof(char));
    char *filereadbuf = (char *)malloc(bufferSize + sizeof(char));

    if ((socketbuf == NULL) || (filereadbuf == NULL))
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE); // Exit with error code
    }

    int bytes_received;
    int bytes_read;

    while ((bytes_received = recv(this_datap->connection_fd, socketbuf, BUFFERSIZE - 1, 0)) > 0)
    {

        socketbuf[bytes_received] = '\0'; // Null-terminate the received data
        // printf("Received: %s\n", socketbuf);

        /* code */
        syslog(LOG_DEBUG, "Writing %s to %s", socketbuf, datadir);
        printf("thread writing file: %s", socketbuf);
        fprintf(file, "%s", socketbuf);
        fflush(file);

        if (socketbuf[bytes_received - 1] == '\n')
        {

            // Lock the mutex before accessing the shared resource
            pthread_mutex_lock(&counter_mutex);

            // Critical section

            rewind(file);
            while ((bytes_read = fread(filereadbuf, 1, BUFFERSIZE, file)) > 0)
            {
                syslog(LOG_DEBUG, "read: %i", bytes_read);
                // printf("thread Bytes read: %i\n", bytes_read);

                int sent;
                if ((sent = send(this_datap->connection_fd, filereadbuf, bytes_read, 0)) == -1)
                {
                    perror("Send failed");
                    close(this_datap->connection_fd);
                    fclose(file);
                    pthread_mutex_unlock(&counter_mutex);
                    exit(EXIT_FAILURE);
                }
                else
                {
                    syslog(LOG_DEBUG, "sent: %i", sent);
                    // printf("thread Packet end bytes sent: %i\r\n", sent);
                }
            }
            // Unlock the mutex after accessing the shared resource
            pthread_mutex_unlock(&counter_mutex);
            break;
        }
    }
    // printf("closed with: %i", close(this_datap->connection_fd));
    //   exit(EXIT_FAILURE);

    free(socketbuf);
    free(filereadbuf);
    // syslog(LOG_DEBUG, "Closed connection from %s", s);
    close(this_datap->connection_fd);
    this_datap->done = true;
    // exit(EXIT_SUCCESS);
    return NULL;
}

void *thread_timer(void *arg)
{

    char buffer[100];
    time_t current_time;
    struct tm *time_info;
    printf("hello timer");

    while (1)
    {
        // Get the current time
        time(&current_time);
        time_info = localtime(&current_time);

        // Format the time according to RFC 2822 compliant strftime format
        // Example format: "timestamp: Fri, 21 Nov 1997 09:55:06 +0000\n"
        strftime(buffer, sizeof(buffer), "timestamp: %a, %d %b %Y %H:%M:%S %z\n", time_info);
        pthread_mutex_lock(&counter_mutex);

        // Write the formatted timestamp to the file
        fputs(buffer, file);
        printf("timerwrite: %s", buffer);
        pthread_mutex_unlock(&counter_mutex);

        // Sleep for 10 seconds
        sleep(10);
    }

    return 0;
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

    // Slist
    slist_data_t *datap = NULL;

    SLIST_HEAD(slisthead, slist_data_s)
    head;
    SLIST_INIT(&head);

    if (pthread_mutex_init(&counter_mutex, NULL) != 0)
    {
        fprintf(stderr, "Mutex initialization failed\n");
        return 1;
    }

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
        // printf("daeeeeeemon!");
        daemon = true;
    }

    if (!daemon || (fork() == 0))
    {
        { // child
            // close(sockfd);
            pthread_t timer_thread;
            if (pthread_create(&timer_thread, NULL, thread_timer, NULL))
            {
                printf("timer Thread failed.");
                syslog(LOG_ERR, "timer Thread failed.");
                closelog();
                exit(1);
            }

            if (listen(sockfd, BACKLOG) == -1)
            {
                perror("listen");
                printf("main listen error.");
                exit(1);
            }

            sa.sa_handler = sigchld_handler; // reap all dead processes
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = SA_RESTART;
            if (sigaction(SIGCHLD, &sa, NULL) == -1)
            {
                printf("main sigaction error.");
                perror("sigaction");
                exit(1);
            }

            printf("main server: waiting for connections...\n");

            file = fopen(datadir, "w+");
            if (file == NULL)
            {
                printf("Error! File");
                syslog(LOG_ERR, "Error opening file!");
                closelog();
                exit(1);
            }

            while (1)
            { // main accept() loop
                sin_size = sizeof their_addr;
                printf("main wait for new accept");
                new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
                if (new_fd == -1)
                {
                    perror("accept");
                    printf("main accept error.");

                    continue;
                }

                inet_ntop(their_addr.ss_family,
                          get_in_addr((struct sockaddr *)&their_addr),
                          s, sizeof s);

                syslog(LOG_DEBUG, "Accepted connection from %s", s);
                printf("server: got connection from %s\n", s);

                pthread_t thread;
                datap = malloc(sizeof(slist_data_t));
                datap->done = false;
                datap->connection_fd = new_fd;

                if (pthread_create(&thread, NULL, thread_connection, datap))
                {
                    printf("Thread failed.");
                    syslog(LOG_ERR, "Thread failed.");
                    closelog();
                    exit(1);
                }
                datap->thread_id = thread;

                printf("newthread: %li\n", datap->thread_id);
                SLIST_INSERT_HEAD(&head, datap, entries);

                // Read1.
                // printf("Threads: ");
                SLIST_FOREACH(datap, &head, entries)
                {
                    // printf("%ld, ", datap->thread_id);
                    if (datap->done)
                    {
                        pthread_join(datap->thread_id, NULL);
                    }
                }
                // printf("\n");
            }

            fclose(file);
        }
    } // end child

    // close(new_fd); // parent doesn't need this
    // fclose(file);
    // closelog();

    return 0;
}