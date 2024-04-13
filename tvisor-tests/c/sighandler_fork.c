#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int child_forked = 0;

static void handler1(int sig)
{
    if (!child_forked) {
        pid_t pid = fork();
        switch (pid) {
        case 0: // Child process
            printf("Child process started, PID: %d\n", getpid());
            // Simulate some operation in child
            _exit(0); // Child process exits immediately
            break;
        case -1: // Fork failed
            printf("fork failed: %s\n", strerror(errno));
            break;
        default: // Parent process
            child_forked = 1; // Mark that a child has been forked
            printf("Parent process, PID: %d, waiting for child PID: %d\n", getpid(), pid);
            int status;
            waitpid(pid, &status, 0); // Wait for the child to exit
            if (WIFEXITED(status)) {
                printf("Child PID: %d exited with status: %d\n", pid, WEXITSTATUS(status));
            } else {
                printf("Child PID: %d did not exit normally\n", pid);
            }
            break;
        }
    }
}
static void *start(void *arg)
{
    raise(SIGRTMIN+1); // Trigger the signal handler that may fork
    return 0;
}

int main(void)
{
    pthread_t t;
    int r;

    if (signal(SIGRTMIN+1, handler1) == SIG_ERR)
        printf("registering signal handler failed: %s\n", strerror(errno));

    r = pthread_create(&t, NULL, start, NULL);
    if (r)
        printf("pthread_create failed: %s\n", strerror(r));

    r = pthread_join(t, NULL);
    if (r)
        printf("pthread_join failed: %s\n", strerror(r));

    // Check if the child was forked.
    if (!child_forked) {
        printf("Child was not forked\n");
        return 1;
    }
    return 0;
}
