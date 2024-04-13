#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

int main() {
    sigset_t new_mask, old_mask, pending_mask;

    // Initialize new_mask and add SIGINT to it
    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGINT);

    // Block SIGINT and save current signal mask
    if (sigprocmask(SIG_BLOCK, &new_mask, &old_mask) < 0) {
        perror("sigprocmask - SIG_BLOCK");
        return 1;
    }

    // Sleep for 1 seconds to simulate some work being done
    sleep(1);

    // Check if SIGINT was raised during this time
    if (sigpending(&pending_mask) < 0) {
        perror("sigpending");
    } else {
        if (sigismember(&pending_mask, SIGINT)) {
            printf("SIGINT was pending.\n");
        }
    }

    // Restore the original signal mask, unblocking SIGINT
    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0) {
        perror("sigprocmask - SIG_SETMASK");
        return 1;
    }

    // Try to block SIGSYS, which should not fail.
    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGSYS);
    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0) {
        perror("sigprocmask - SIG_SETMASK");
        return 1;
    }
    return 0;
}
