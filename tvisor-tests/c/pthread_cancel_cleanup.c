#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void cleanup(void *arg)
{
    *(int *)arg = 1;
}

static void *start_single(void *arg)
{
    pthread_cleanup_push(cleanup, arg);
    sleep(3);
    pthread_cleanup_pop(0);
    return 0;
}

int main(void)
{
    pthread_t td;
    int r;
    void *res;
    int foo[4];

    foo[0] = 0;
    if ((r = pthread_create(&td, 0, start_single, foo)) != 0) {
        fprintf(stderr, "Error creating thread: %s\n", strerror(r));
        return 1;
    }
    sleep(0.5);
    if ((r = pthread_cancel(td)) != 0) {
        fprintf(stderr, "Error cancelling thread: %s\n", strerror(r));
        return 1;
    }
    if ((r = pthread_join(td, &res)) != 0) {
        fprintf(stderr, "Error joining canceled thread: %s\n", strerror(r));
        return 1;
    }
    if (res != PTHREAD_CANCELED || foo[0] != 1) {
        fprintf(stderr, "Cleanup handler failed to run or exited with wrong status: %d != 1\n", foo[0]);
        return 1;
    }
    return 0;
}
