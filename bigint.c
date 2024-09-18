#include "bigint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to initialize a BigInt
void BigInt_init(BigInt *bigint, size_t size) {
    bigint->digits = (unsigned char *)malloc(size);
    if (bigint->digits == NULL) {
        perror("Failed to allocate memory for BigInt");
        exit(EXIT_FAILURE);
    }
    memset(bigint->digits, 0, size);
    bigint->size = size;
}

// Function to free a BigInt
void BigInt_free(BigInt *bigint) {
    free(bigint->digits);
    bigint->digits = NULL;
    bigint->size = 0;
}

// Function to reverse a byte array
static void reverse_bytes(unsigned char *array, size_t length) {
    size_t i;
    for (i = 0; i < length / 2; i++) {
        unsigned char temp = array[i];
        array[i] = array[length - 1 - i];
        array[length - 1 - i] = temp;
    }
}

// Function to print a BigInt
void BigInt_print(const BigInt *bigint) {
    for (size_t i = 0; i < bigint->size; i++) {
        printf("%d", bigint->digits[i]);
    }
    printf("\n");
}