#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <signal>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int sig = atoi(argv[1]); // Convert the command line argument to an integer
    pid_t pid = getpid(); // Get the current process ID
    pid_t tid = syscall(SYS_gettid); // Get the current thread ID

    // Call tgkill to send the signal to the main thread of the current process
    int result = syscall(SYS_tgkill, pid, tid, sig);

    if (result == 0) {
        printf("Signal %d successfully sent to thread %d of process %d.\n", sig, tid, pid);
    } else {
        perror("tgkill failed");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}