#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define ALT_STACK_SIZE 1024*1024  // 1MB

// Custom signal handler
void signal_handler(int signum) {
    printf("Received signal %d\n", signum);
}

int main() {
    stack_t ss, old_ss;
    struct sigaction sa;

    // Allocate alternate stack
    ss.ss_sp = malloc(ALT_STACK_SIZE);
    // Write some dummy value to the top and bottom of the stack as a sanity check.
    *(int*)ss.ss_sp = 0xdeadbeef;
    *(int*)(ss.ss_sp + ALT_STACK_SIZE - sizeof(int)) = 0xdeadbeef;
    if (ss.ss_sp == NULL) {
        perror("malloc");
        return 1;
    }
    ss.ss_size = ALT_STACK_SIZE;
    ss.ss_flags = 0;

    // Set the alternate stack
    if (sigaltstack(&ss, &old_ss) == -1) {
        perror("sigaltstack set");
        return 1;
    }

    // Set up the signal handler
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_ONSTACK;

    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }

    // Raise the signal to test the handler
    if (raise(SIGUSR1) != 0) {
        perror("raise");
        return 1;
    }

    // Restore the old stack.
    if (sigaltstack(&old_ss, NULL) == -1) {
        perror("sigaltstack restore");
        return 1;
    }

    if (sigaction(SIGSYS, &sa, NULL) != -1 || errno != EINVAL) {
        perror("sigaction for SIGSYS should fail with EINVAL");
        return 1;
    }
    return 0;
}
