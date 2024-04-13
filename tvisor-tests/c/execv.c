#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[], char *envp[]) {
    // Check if our custom environment variable is set
    char *myEnvVar = getenv("MY_CUSTOM_ENV");
    if (myEnvVar != NULL) {
        // If the environment variable is set, print its value and exit
        printf("MY_CUSTOM_ENV is: %s\n", myEnvVar);
        printf("UID in new exec: %d\n", getuid());
    } else {
        // If the environment variable is not set, set it and re-execute the program
        char *newEnv[] = {"MY_CUSTOM_ENV=HelloWorld", NULL}; // New environment array
        char *newArgv[] = {argv[0], NULL}; // Arguments for the new execution, keeping it simple

        // Use execle to re-execute the program with the new environment
        execle(argv[0], argv[0], NULL, newEnv);
        perror("execle"); // If execle returns, it's an error
        return 1;
    }

    return 0;
}
