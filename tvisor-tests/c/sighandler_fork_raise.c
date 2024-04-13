#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

static int exp_c0 = 0;
static int exp_c1 = 1;

static volatile int c0;
static volatile int c1;
static volatile int child;

// Overrides printf to prefix with process id:
#define printf(...) { printf("%d: ", getpid()); printf(__VA_ARGS__); }

static void handler1(int sig)
{
    c1++;
    printf("Signal handler1 triggered, c1=%d\n", c1);
    int fork_ret = fork();
    switch (fork_ret) {
    case 0:
        child=1;
        printf("Child process created: pid=%d\n", getpid());
        break;
    case -1:
        printf("fork failed: %s\n", strerror(errno));
        break;
    default:
        printf("Fork successful: child_pid=%d\n", fork_ret);
    }
}

static void *start(void *arg)
{
    time_t start_time = time(NULL);
    sleep(1);
    // Check the continuation is actually after 1 second.
    time_t current_time = time(NULL);
    if (current_time - start_time < 1) {
        if (child) {
            printf("Child: Continuation is not after 1 second: %d\n", current_time - start_time);
        } else {
            printf("Parent: Continuation is not after 1 second: %d\n", current_time - start_time);
        }
        _exit(1);
    }

    int i,r,s;
    if (child) {
        printf("Start fn in Child\n");
    } else {
        printf("Start fn in Parent\n");
    }

    if (child) {
        _exit(0);
    }

    start_time = time(NULL);
    int timeout = 10;

    while (c1 < exp_c1) {
        current_time = time(NULL);
        if (current_time - start_time > timeout) {
            printf("Timeout reached while waiting for c1 to reach %d\n", exp_c1);
            _exit(1);
        }
        printf("Waiting for c1 to reach %d, c1=%d\n", exp_c1, c1);
        sleep(1);
    }

    printf("Waiting for forked children...\n");

    for (i = 0; i < exp_c1; i++) {
        r = wait(&s);
        if (r == -1) {
            printf("wait failed: %s\n", strerror(errno));
            _exit(1);
        } else if (!WIFEXITED(s) || WTERMSIG(s)) {
            printf("child failed: pid:%d status:%d\n", r, s);
            _exit(1);
        } else {
            printf("child exited: pid:%d status:%d\n", r, s);
        }
    }
    printf("All forked children have been waited on\n");
    return 0;
}


int main(void)
{
    pthread_t t;
    void *p;
    int r, i, s;

    printf("Main: registering signal handlers\n");
    if (signal(SIGRTMIN+1, handler1) == SIG_ERR) {
        printf("Registering signal handler1 failed: %s\n", strerror(errno));
    }

    r = pthread_create(&t, 0, start, 0);
    if (r) {
        printf("pthread_create failed: %s\n", strerror(r));
    } else {
        printf("Thread created successfully\n");
    }

    for (i = 0; i < exp_c1; i++) {
        r = pthread_kill(t, SIGRTMIN+1);
        if (r)
            printf("pthread_kill failed: %s\n", strerror(r));
    }
    printf("Signals sent to thread: %d\n", i);

    r = pthread_join(t, &p);
    if (r) {
        printf("pthread_join failed: %s\n", strerror(r));
    } else {
        printf("Thread joined successfully\n");
    }

    return 0;
}
