#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define NUM_THREADS 5
#define NUM_INCREMENTS 1000000

// Global counter
long long globalCounter = 0;

// Mutex for thread-safe increment
pthread_mutex_t counterMutex = PTHREAD_MUTEX_INITIALIZER;

// Thread function to increment the counter
void* incrementCounter(void* arg) {
    for (int i = 0; i < NUM_INCREMENTS; i++) {
        pthread_mutex_lock(&counterMutex);
        globalCounter++;
        pthread_mutex_unlock(&counterMutex);
    }
    return NULL;
}

int main() {
    pthread_t threads[NUM_THREADS];
    int thread_args[NUM_THREADS];
    int i;

    // Create threads
    for (i = 0; i < NUM_THREADS; i++) {
        thread_args[i] = i;
        if (pthread_create(&threads[i], NULL, incrementCounter, (void*) &thread_args[i])) {
            fprintf(stderr, "Error creating thread %d\n", i);
            return 1;
        }
    }

    // Wait for all threads to complete
    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    // Print the global counter value
    printf("Final global counter value: %lld\n", globalCounter);

    // Clean up and exit
    pthread_mutex_destroy(&counterMutex);
    return 0;
}
