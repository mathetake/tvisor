#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t pid1, pid2;

    // First fork
    pid1 = fork();
    if (pid1 == 0) {
        // First child process

        // Second fork by the first child
        pid2 = fork();
        if (pid2 == 0) {
            // Grandchild process (second child of the original process)
            printf("Grandchild UID: %d\n", getuid());
        } else {
            // First child process waits for its child (the grandchild)
            wait(NULL);
            printf("First child UID: %d\n", getuid());
        }
    } else {
        // Parent process waits for the first child to finish
        wait(NULL);
    }

    return 0;
}
