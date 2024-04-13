#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main() {
    sigset_t sigset;

    // Block SIGILL
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGILL);
    if (sigprocmask(SIG_BLOCK, &sigset, NULL) == -1) {
        perror("sigprocmask");
        exit(EXIT_FAILURE);
    }

#if defined(__x86_64__) || defined(__i386__)
    asm("ud2");
#elif defined(__aarch64__)
    asm("udf #0");
#else
    printf("Unsupported architecture.\n");
    return 1;
#endif

    return 0;
}
