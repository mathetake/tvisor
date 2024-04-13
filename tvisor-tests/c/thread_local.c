#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

// Define a thread-local variable
_Thread_local int thread_counter = 0;

// Thread function
void* thread_function(void* arg) {
    int id = *((int*)arg);
    thread_counter = id;

    printf("Thread %d: Initial thread_counter = %d\n", id, thread_counter);

    // Modify the thread-local variable
    for (int i = 0; i < 500; ++i) {
        thread_counter++;
        printf("Thread %d: thread_counter = %d\n", id, thread_counter);
    }

    return NULL;
}

int main() {
    const int num_threads = 3;
    pthread_t threads[num_threads];
    int thread_ids[num_threads];

    // Create threads
    for (int i = 0; i < num_threads; ++i) {
        thread_ids[i] = i;
        if (pthread_create(&threads[i], NULL, thread_function, &thread_ids[i]) != 0) {
            perror("Failed to create thread");
            return 1;
        }
    }

    // Join threads
    for (int i = 0; i < num_threads; ++i) {
        if (pthread_join(threads[i], NULL) != 0) {
            perror("Failed to join thread");
            return 1;
        }
    }

    return 0;
}
