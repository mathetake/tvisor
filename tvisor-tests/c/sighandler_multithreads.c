#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>

void *raiseSIGTERM(void *arg) {
    sleep(1); // Delay to ensure main thread is ready for signals
    printf("Thread 1: Raising SIGTERM signal.\n");
    raise(SIGTERM);
}

void *raiseSIGINT(void *arg) {
    sleep(1); // Delay to ensure main thread is ready for signals
    printf("Thread 2: Raising SIGINT signal.\n");
    raise(SIGINT);
}

void signalHandler(int signalNumber) {
    if (signalNumber == SIGINT) {
        printf("Thread UID at SIGINT: %d\n", getuid());
        printf("Received SIGINT\n");
    } else if (signalNumber == SIGTERM) {
        printf("Thread UID at SIGTERM: %d\n", getuid());
        printf("Received SIGTERM\n");
    } else {
        printf("Received signal: %d\n", signalNumber);
    }
}

int main() {
    pthread_t tid1, tid2;

    // Block SIGINT and SIGTERM in the main thread and all spawned threads
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    // Register signal handlers
    struct sigaction sa;
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // or SA_RESTART to restart syscalls if needed
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("sigaction");
        exit(1);
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("sigaction");
        exit(1);
    }

    // Create threads
    pthread_create(&tid1, NULL, raiseSIGTERM, NULL);
    pthread_create(&tid2, NULL, raiseSIGINT, NULL);

    sleep(3); // Simulate some work

    printf("Main thread UID at the end: %d\n", getuid());
    return 0;
}
