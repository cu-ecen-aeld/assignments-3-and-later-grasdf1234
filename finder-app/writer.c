

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

int main(int argc, char *argv[])
{
    openlog("writer", 0, LOG_USER);

    // test num params
    if (argc != 3)
    {
        printf("Two arguments expected. Arguments are: %i\n.", argc - 1);

        return 1; // error out
    }

    FILE *file;

    file = fopen(argv[1], "w");

    if (file == NULL)
    {
        printf("Error!");
        syslog(LOG_ERR, "Error opening file!");
        closelog();
        exit(1);
    }
    else
    {
        /* code */
        syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
        fprintf(file, "%s", argv[2]);
        fclose(file);
        closelog();

        exit(0);
    }

    fclose(file);
    closelog();

    return 1;
}