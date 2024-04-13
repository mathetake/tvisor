#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    char *cwd;
    char buffer[1024];

    // Get the current working directory
    cwd = getcwd(buffer, sizeof(buffer));

    // Check for errors
    if (cwd == NULL) {
        perror("getcwd() error");
        return 1;
    }

    // Print the current working directory
    printf("Current working directory: %s\n", cwd);

    return 0;
}
