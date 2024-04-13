#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

static void *start_async(void *arg)
{
    printf("child: start\n");
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0);
	printf("child: sem_post\n");
	sem_post(arg);
	printf("child: sem_post done\n");
	for (;;);
}

int main(void)
{
	pthread_t td;
	sem_t sem1;
	void *res;

    printf("main: start\n");
    sem_init(&sem1, 0, 0);

	/* Asynchronous cancellation */
	printf("main: start_async\n");
	pthread_create(&td, 0, start_async, &sem1);
	printf("main: sem_wait\n");
	while (sem_wait(&sem1));
	printf("main: sem_wait done\n");
	pthread_cancel(td);
	printf("main: pthread_join\n");
	pthread_join(td, &res);
	printf("main: pthread_join done\n");
    if (res != PTHREAD_CANCELED) {
        printf("main: unexpected result\n");
        return 1;
    }
	return 0;
}
