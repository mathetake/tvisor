#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[]) {
    // Check if an argument is provided
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // Create and open the file for writing
    FILE *file = fopen(argv[1], "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening file '%s': %s\n", argv[1], strerror(errno));
        return 1;
    }

    // Write some content to the file
    fprintf(file, "Hello, file named %s!\n", argv[1]);

    // Close the file
    fclose(file);

    return 0;
}
