// The test program that prints all the arguments passed to it in C.

#include <stdio.h>

int main(int argc, char *argv[]) {
  int i;
  for (i = 0; i < argc; i++) {
    printf("%s\n", argv[i]);
  }
  return 0;
}