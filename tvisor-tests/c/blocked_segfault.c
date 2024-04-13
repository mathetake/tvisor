#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>

int main() {
    sigset_t set;
    int *ptr = NULL;
    size_t pagesize;

    // Block SIGSEGV
    sigemptyset(&set);
    sigaddset(&set, SIGSEGV);
    sigprocmask(SIG_BLOCK, &set, NULL);

    // Cause a segmentation fault by writing to a memory location that we don't have access to
    pagesize = sysconf(_SC_PAGESIZE);
    ptr = mmap(NULL, pagesize, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    *ptr = 1; // Attempt to write to a read-only page

    // Cleanup
    munmap(ptr, pagesize);

    return 0;
}
