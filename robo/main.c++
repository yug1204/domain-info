#include <stdio.h>

int main(void) {
    // Declare and initialize a 3x2 array
    int x[3][2] = { { 0, 1 }, { 2, 3 }, { 4, 5 } };

    // Loop through rows
    for (int i = 0; i < 3; i++) {
        // Loop through columns
        for (int j = 0; j < 2; j++) {
            printf("Element at x[%i][%i]: ", i, j);
            printf("%d\n", x[i][j]);
        }
    }

    return 0;
}
