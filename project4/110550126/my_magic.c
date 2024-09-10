#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    // Seed the random number generator
    srand(time(0));

    // Generate and print random characters
    for (int i = 0; i < 0x10; i++) {
        char ch = 48 + (rand() % (126 - 47) + 1);
        printf("%c", ch);
    }

    // Print a newline for clarity
    return 0;
}
