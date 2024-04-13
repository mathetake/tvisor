#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

static void handler(int sig) {
    printf("Signal handler\n");
}

static void *start(void *arg)
{
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);
    // Check environment variable CLOC_NANO_SLEEP to determine whether to use nanosleep.
    if (getenv("CLOC_NANO_SLEEP") != NULL) {
        printf("Use clock_nanosleep\n");
        struct timespec req;
        req.tv_sec = 1;
        req.tv_nsec = 0;
        clock_nanosleep(CLOCK_REALTIME, 0, &req, NULL);
    } else {
        printf("Use sleep\n");
        sleep(1);
    }
    gettimeofday(&current_time, NULL);

    // Calculate the time difference in microseconds.
    long time_diff = (current_time.tv_sec - start_time.tv_sec) * 1000000L + (current_time.tv_usec - start_time.tv_usec);

    if (time_diff < 1000000L) {
        printf("Continuation is not after 1 second: %ld microseconds <1000000\n", time_diff);
        _exit(1);
    } else {
        printf("Continuation is after 1 second\n", time_diff);
    }
    return 0;
}

#define TARGET_SIGNAL SIGTERM

int main(void)
{
    pthread_t t;
    void *p;
    int r, s;

    if (signal(TARGET_SIGNAL, handler) == SIG_ERR) {
        printf("Registering signal handler1 failed: %s\n", strerror(errno));
        _exit(1);
    }

    // Block the signal to make sure that sleep won't be interrupted.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, TARGET_SIGNAL);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL)) {
        printf("pthread_sigmask failed: %s\n", strerror(errno));
        _exit(1);
    }

    r = pthread_create(&t, 0, start, 0);
    if (r) {
        printf("pthread_create failed: %s\n", strerror(r));
        _exit(1);
    }

    // Sleep for 1 second to ensure that the child thread is sleeping.
    sleep(0.5);

    r = pthread_kill(t, TARGET_SIGNAL);
    if (r) {
        printf("pthread_kill failed: %s\n", strerror(r));
        _exit(1);
    }

    r = pthread_join(t, &p);
    if (r) {
        printf("pthread_join failed: %s\n", strerror(r));
        _exit(1);
    }
    return 0;
}
