#ifndef BIGINT_H
#define BIGINT_H

#include <stddef.h>

// Define the BigInt structure
typedef struct {
    unsigned char *digits; // Array to store the digits of the BigInt
    size_t size;           // Number of bytes currently used
} BigInt;

// Function prototypes
void BigInt_init(BigInt *bigint, size_t size);
void BigInt_free(BigInt *bigint);
BigInt BigInt_from_bytes(const unsigned char *hash, size_t hash_len);
void BigInt_print(const BigInt *bigint);

#endif // BIGINT_H
