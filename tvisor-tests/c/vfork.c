#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    if(getenv("HAS_FORKED")) {
        // If the environment variable is set, don't fork again.
        printf("Child process: PID = %d, PPID = %d. This process will not fork again.\n", getpid(), getppid());
        exit(EXIT_SUCCESS);
    } else {
        // Set an environment variable to prevent further forking
        setenv("HAS_FORKED", "1", 1);

        pid_t pid = vfork();

        if (pid == 0) { // Child process
            printf("Forking once: PID = %d, PPID = %d\n", getpid(), getppid());

            // Execute the same program. The environment variable is inherited, so it won't fork again.
            execlp(argv[0], argv[0], (char *)NULL);

            // If execlp returns, it means it failed
            printf("Failed to execute program\n");
            _exit(EXIT_FAILURE); // Use _exit to avoid flushing stdio buffers of the parent
        } else if (pid > 0) { // Parent process
            wait(NULL); // Wait for the child to terminate
            printf("Parent process: PID = %d. Child process has terminated.\n", getpid());
        } else {
            // vfork failed
            perror("vfork");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
