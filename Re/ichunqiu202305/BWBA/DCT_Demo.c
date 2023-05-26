#include <stdio.h>
#include <math.h>

#define N 8

void dct_1d(double *input, double *output) {
    int k, n;
    double sum;
    const double PI = 3.14159265358979323846;

    for (k = 0; k < N; k++) {
        sum = 0;
        for (n = 0; n < N; n++) {
            sum += input[n] * cos((2 * n + 1) * k * PI / (2 * N));
        }
        output[k] = sum * sqrt(2.0 / N);
    }
}

void dct_2d(double input[N][N], double output[N][N]) {
    int i, j;
    double temp_input[N][N], temp_output[N][N];

    for (i = 0; i < N; i++) {
        dct_1d(input[i], temp_output[i]);
    }

    for (j = 0; j < N; j++) {
        for (i = 0; i < N; i++) {
            temp_input[i][j] = temp_output[i][j];
        }
    }

    for (j = 0; j < N; j++) {
        dct_1d(temp_input[j], temp_output[j]);
    }

    for (i = 0; i < N; i++) {
        for (j = 0; j < N; j++) {
            output[i][j] = temp_output[i][j];
        }
    }
}

int main() {
    int i, j;
    double input[N][N], output[N][N];

    // Initialize input matrix
    for (i = 0; i < N; i++) {
        for (j = 0; j < N; j++) {
            input[i][j] = i + j;
        }
    }

    // Perform DCT
    dct_2d(input, output);

    // Print output matrix
    for (i = 0; i < N; i++) {
        for (j = 0; j < N; j++) {
            printf("%f ", output[i][j]);
        }
        printf("\n");
    }

    return 0;
}
