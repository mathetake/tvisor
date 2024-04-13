#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <errno.h>

int child_tid;

void signal_handler(int sig, siginfo_t *siginfo, void *context) {
    printf("Received signal %d from PID=%d in %ld: payload=%d\n", sig, siginfo->si_pid, syscall(SYS_gettid), siginfo->si_int);
}

void* child_thread(void* arg) {
    struct sigaction sa;

    // Set up the signal handler
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = signal_handler;
    sigaction(SIGUSR1, &sa, NULL);

    child_tid = syscall(SYS_gettid);

    // Simulate doing some work
    printf("Child thread running, PID: %ld, TID: %ld\n", (long)getpid(), (long)child_tid);
    sleep(5); // Sleep to simulate work and ensure it's alive to receive the signal

    return NULL;
}

int main(void) {
    pid_t pid = getpid();
    printf("Parent PID: %d\n", pid);

    // Create the child thread
	pthread_t t;
    if (pthread_create(&t, NULL, child_thread, NULL) != 0) {
        perror("pthread_create failed");
        exit(EXIT_FAILURE);
    }

    // Give time for child thread to initialize
    sleep(1);

    // Prepare the siginfo_t structure for sending with rt_tgsigqueueinfo
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    info.si_signo = SIGUSR1;
    info.si_code = SI_QUEUE;
    info.si_pid = pid; // Sender's PID
    info.si_uid = getuid(); // Sender's UID
    info.si_int = 123; // Example data payload

    printf("PID: %d, TID: %d\n", pid, child_tid);

    // Correctly send the signal to the child thread
    if (syscall(SYS_rt_tgsigqueueinfo, pid, child_tid, SIGUSR1, &info) != 0) {
        perror("rt_tgsigqueueinfo failed");
        exit(EXIT_FAILURE);
    }

    sleep(1);
    return 0;
}
