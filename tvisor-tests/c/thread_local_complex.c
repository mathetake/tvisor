#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

// Define thread-local variables representing tools with non-zero initial values
_Thread_local int toolA = 5;
_Thread_local int toolB = 10;
_Thread_local int toolC = 15;

// Function to simulate a complex task performed by each worker
void* worker_task(void* arg) {
    int worker_id = *((int*)arg);

    // Print the address of the TLS variable
    printf("Thread %d: Address of toolA = %p\n", worker_id, (void*)&toolA);
    printf("Thread %d: Address of toolB = %p\n", worker_id, (void*)&toolB);
    printf("Thread %d: Address of toolC = %p\n", worker_id, (void*)&toolC);


    printf("Worker %d current value: ToolA = %d, ToolB = %d, ToolC = %d\n", worker_id, toolA, toolB, toolC);

    // Simulate modifying the tools in a unique way for each worker
    toolA += worker_id;
    toolB *= worker_id;
    toolC -= worker_id;

    // Perform additional operations using the modified tools
    int result = toolA * toolB + toolC;
    printf("Worker %d: Result of operation = %d\n", worker_id, result);

    return NULL;
}

int main() {
    const int num_workers = 4;
    pthread_t workers[num_workers];
    int worker_ids[num_workers];

    // Print the address of the TLS variable
    printf("Main thread: Address of toolA = %p\n", (void*)&toolA);
    printf("Main thread: Address of toolB = %p\n", (void*)&toolB);
    printf("Main thread: Address of toolC = %p\n", (void*)&toolC);

    // Print the main thread's initial tool values.
    printf("Main thread current value: ToolA = %d, ToolB = %d, ToolC = %d\n", toolA, toolB, toolC);

    // Create worker threads
    for (int i = 0; i < num_workers; ++i) {
        worker_ids[i] = i + 1; // Assign a unique ID to each worker
        if (pthread_create(&workers[i], NULL, worker_task, &worker_ids[i]) != 0) {
            perror("Failed to create worker thread");
            return 1;
        }
    }

    // Join worker threads
    for (int i = 0; i < num_workers; ++i) {
        if (pthread_join(workers[i], NULL) != 0) {
            perror("Failed to join worker thread");
            return 1;
        }
    }

    return 0;
}
