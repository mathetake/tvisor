#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>

void printSignalAction(int signum) {
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    if (sigaction(signum, NULL, &act) != -1) {
        if (act.sa_handler == SIG_DFL) {
            printf("Signal %d has default handling (SIG_DFL)\n", signum);
        } else if (act.sa_handler == SIG_IGN) {
            printf("Signal %d is ignored (SIG_IGN)\n", signum);
        } else {
            printf("Signal %d has custom handler (%p)\n", signum, (void*)act.sa_handler);
        }
    } else {
        perror("sigaction");
        printf("Error retrieving action for signal %d\n", signum);
    }
}


int main() {
    sigset_t sigset;
    int i, result;

    // Initialize the signal set to empty
    sigemptyset(&sigset);

    // Retrieve the current set of blocked signals for the calling thread
    if (pthread_sigmask(SIG_BLOCK, NULL, &sigset) != 0) {
        perror("pthread_sigmask");
        return 1;
    }

    // Iterate through the list of possible signals and check if they are blocked
    for (i = 1; i < NSIG; ++i) {
        result = sigismember(&sigset, i);
        if (result == -1) {
            perror("sigismember");
            continue;
        }

        if (result == 1) {
            printf("Signal %d is blocked.\n", i);
        } else {
            printf("Signal %d is not blocked.\n", i);
        }
    }

    for (int i = 1; i < NSIG; i++) {
        printSignalAction(i);
    }

    return 0;
}
