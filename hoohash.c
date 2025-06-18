/*
 * This file is part of Hoosat Oy's project.
 *
 * Copyright (C) 2024 Toni Lukkaroinen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Author: Toni Lukkaroinen
 * Company: Hoosat Oy
 */

#include <fenv.h>
#include <stdint.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <blake3.h>
#include "bigint.h"
#include "hoohash.h"

void show_fe_current_rounding_direction(void)
{
    printf("current rounding direction:  ");
    switch (fegetround())
    {
    case FE_TONEAREST:
        printf("FE_TONEAREST");
        break;
    case FE_DOWNWARD:
        printf("FE_DOWNWARD");
        break;
    case FE_UPWARD:
        printf("FE_UPWARD");
        break;
    case FE_TOWARDZERO:
        printf("FE_TOWARDZERO");
        break;
    default:
        printf("unknown");
    };
    printf("\n");
}

uint8_t *to_little_endian_uint8_t_pointer(const uint8_t *value, size_t size)
{
    // Allocate memory for the result
    uint8_t *little_endian_value = (uint8_t *)malloc(size);
    if (little_endian_value == NULL)
    {
        return NULL; // Memory allocation failed
    }

#if __BYTE_ORDER == __LITTLE_ENDIAN
    // If the system is already little-endian, copy the value as is
    memcpy(little_endian_value, value, size);
#else
    // If the system is big-endian, we need to reverse the byte order
    for (size_t i = 0; i < size; i++)
    {
        little_endian_value[i] = value[size - 1 - i];
    }
#endif

    return little_endian_value;
}

uint8_t *to_big_endian_uint8_t_pointer(const uint8_t *value, size_t size)
{
    // Allocate memory for the result
    uint8_t *big_endian_value = (uint8_t *)malloc(size);
    if (big_endian_value == NULL)
    {
        return NULL; // Memory allocation failed
    }

#if __BYTE_ORDER == __BIG_ENDIAN
    // If the system is already big-endian, copy the value as is
    memcpy(big_endian_value, value, size);
#else
    // If the system is little-endian, we need to reverse the byte order
    for (size_t i = 0; i < size; i++)
    {
        big_endian_value[i] = value[size - 1 - i];
    }
#endif

    return big_endian_value;
}

// Function to convert a byte array to BigInt
BigInt toBig(uint8_t *hash, size_t hash_len)
{
    BigInt bigint;
    BigInt_init(&bigint, hash_len);
    printf("Before Big endian: %s\n", hash);
    hash = to_big_endian_uint8_t_pointer(hash, hash_len);
    printf("Big endian: %s\n", hash);
    memcpy(bigint.digits, hash, hash_len);
    return bigint;
}

char *encodeHex(const uint8_t *bytes, size_t length)
{
    // Each byte is represented by 2 hex characters, plus 1 for the null terminator
    char *hexStr = (char *)malloc(length * 2 + 1);
    if (hexStr == NULL)
    {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < length; i++)
    {
        snprintf(hexStr + i * 2, 3, "%02x", bytes[i]);
    }
    return hexStr;
}

uint8_t *decodeHex(const char *hexStr, size_t *outSize)
{
    size_t len = strlen(hexStr);
    if (len % 2 != 0)
    {
        fprintf(stderr, "Invalid hex string length.\n");
        return NULL;
    }

    *outSize = len / 2;
    uint8_t *bytes = (uint8_t *)malloc(*outSize);
    if (bytes == NULL)
    {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < *outSize; ++i)
    {
        char high = hexStr[2 * i];
        char low = hexStr[2 * i + 1];
        bytes[i] = (uint8_t)(((high >= '0' && high <= '9') ? high - '0' : high - 'a' + 10) << 4 |
                             ((low >= '0' && low <= '9') ? low - '0' : low - 'a' + 10));
    }

    return bytes;
}

void split_uint8_array_to_uint64(const uint8_t arr[32], uint64_t out[4])
{
    for (int i = 0; i < 4; i++)
    {
        out[i] = 0;
        for (int j = 0; j < 8; j++)
        {
            out[i] |= (uint64_t)arr[i * 8 + j] << (56 - 8 * j);
        }
    }
}

xoshiro_state xoshiro_init(const uint8_t *bytes)
{
    xoshiro_state state;
    // Copy the 32 bytes (256 bits) from hashArray into the state variables
    state.s0 = *(uint64_t *)(&bytes[0]);
    state.s1 = *(uint64_t *)(&bytes[8]);
    state.s2 = *(uint64_t *)(&bytes[16]);
    state.s3 = *(uint64_t *)(&bytes[24]);
    return state;
}

uint64_t rotl64(const uint64_t x, int k)
{
    return (x << k) | (x >> (64 - k));
}

uint64_t xoshiro_gen(xoshiro_state *x)
{
    uint64_t res = rotl64(x->s0 + x->s3, 23) + x->s0;
    uint64_t t = x->s1 << 17;

    x->s2 ^= x->s0;
    x->s3 ^= x->s1;
    x->s1 ^= x->s2;
    x->s0 ^= x->s3;

    x->s2 ^= t;
    x->s3 = rotl64(x->s3, 45);

    return res;
}

// Complex nonlinear transformations
double MediumComplexNonLinear(double x)
{
    return exp(sin(x) + cos(x));
}

double IntermediateComplexNonLinear(double x)
{
    if (x == PI / 2 || x == 3 * PI / 2)
    {
        return 0; // Avoid singularity
    }
    return sin(x) * cos(x) * tan(x);
}

double HighComplexNonLinear(double x)
{
    return 1.0 / sqrt(fabs(x) + 1);
}

#define COMPLEX_TRANSFORM_MULTIPLIER 0.000001

double ComplexNonLinear(double x)
{
    double transformFactorOne = fmod(x * COMPLEX_TRANSFORM_MULTIPLIER, 8) / 8;
    double transformFactorTwo = fmod(x * COMPLEX_TRANSFORM_MULTIPLIER, 4) / 4;
    // printf("%f\n", transformFactorOne);
    // printf("%f\n", transformFactorTwo);
    if (transformFactorOne < 0.33)
    {

        if (transformFactorTwo < 0.25)
        {
            return MediumComplexNonLinear(x + (1 + transformFactorTwo));
        }
        else if (transformFactorTwo < 0.5)
        {
            return MediumComplexNonLinear(x - (1 + transformFactorTwo));
        }
        else if (transformFactorTwo < 0.75)
        {
            return MediumComplexNonLinear(x * (1 + transformFactorTwo));
        }
        else
        {
            return MediumComplexNonLinear(x / (1 + transformFactorTwo));
        }
    }
    else if (transformFactorOne < 0.66)
    {
        if (transformFactorTwo < 0.25)
        {
            return IntermediateComplexNonLinear(x + (1 + transformFactorTwo));
        }
        else if (transformFactorTwo < 0.5)
        {
            return IntermediateComplexNonLinear(x - (1 + transformFactorTwo));
        }
        else if (transformFactorTwo < 0.75)
        {
            return IntermediateComplexNonLinear(x * (1 + transformFactorTwo));
        }
        else
        {
            return IntermediateComplexNonLinear(x / (1 + transformFactorTwo));
        }
    }
    else
    {
        if (transformFactorTwo < 0.25)
        {
            return HighComplexNonLinear(x + (1 + transformFactorTwo));
        }
        else if (transformFactorTwo < 0.5)
        {
            return HighComplexNonLinear(x - (1 + transformFactorTwo));
        }
        else if (transformFactorTwo < 0.75)
        {
            return HighComplexNonLinear(x * (1 + transformFactorTwo));
        }
        else
        {
            return HighComplexNonLinear(x / (1 + transformFactorTwo));
        }
    }
}

// These matter to precision.
#define COMPLEX_OUTPUT_CLAMP 1000000000
#define PRODUCT_VALUE_SCALE_MULTIPLIER 0.1

double ForComplex(double forComplex)
{
    double complex;
    double rounds = 1;
    complex = ComplexNonLinear(forComplex);
    while (isnan(complex) || isinf(complex))
    {
        forComplex = forComplex * 0.1;
        if (forComplex <= 0.0000000000001)
        {
            return 0 * (double)rounds;
        }
        rounds++;
        printf("[forComplex] Input %0.64f, Output %0.12f\n", forComplex, complex);
    }
    return complex * (double)rounds;
}

void generateHoohashMatrix(uint8_t *hash, double mat[64][64])
{
    xoshiro_state state = xoshiro_init(hash);
    double normalize = 1000000.f;
    for (int i = 0; i < 64; i++)
    {
        for (int j = 0; j < 64; j++)
        {
            uint64_t val = xoshiro_gen(&state);
            uint32_t lower_4_bytes = val & 0xFFFFFFFF;
            mat[i][j] = (double)lower_4_bytes / (double)UINT32_MAX * normalize;
        }
    }
}

double TransformFactor(double x)
{
    const double granularity = 1024.0;
    return fmod(x, granularity) / granularity;
}

void ConvertBytesToUint32Array(uint32_t *H, const uint8_t *bytes)
{
    for (int i = 0; i < 8; i++)
    {
        H[i] = ((uint32_t)bytes[i * 4] << 24) |
               ((uint32_t)bytes[i * 4 + 1] << 16) |
               ((uint32_t)bytes[i * 4 + 2] << 8) |
               (uint32_t)bytes[i * 4 + 3];
    }
}
void printHash(unsigned char *hash, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void HoohashMatrixMultiplication(double mat[64][64], const uint8_t *hashBytes, uint8_t *output, uint64_t nonce)
{
    uint8_t scaledValues[32] = {0};
    uint8_t vector[64] = {0};
    double product[64] = {0};
    uint8_t result[32] = {0};
    uint32_t H[8] = {0};
    ConvertBytesToUint32Array(H, hashBytes);
    double hashMod = (double)(H[0] ^ H[1] ^ H[2] ^ H[3] ^ H[4] ^ H[5] ^ H[6] ^ H[7]);
    // printf("Hashmod: %f\n", hashMod);
    double nonceMod = (nonce & 0xFF);
    // printf("noncemod: %f\n", nonceMod);
    double divider = 0.0001;
    double multiplier = 1234;
    double sw = 0.0;

    for (int i = 0; i < 32; i++)
    {
        vector[2 * i] = hashBytes[i] >> 4;
        vector[2 * i + 1] = hashBytes[i] & 0x0F;
    }
    // printf("Vector: ");
    // printHash(vector, 64);

    for (int i = 0; i < 64; i++)
    {
        for (int j = 0; j < 64; j++)
        {
            if (sw <= 0.02)
            {
                double input = (mat[i][j] * hashMod * (double)vector[j] + nonceMod);
                // printf("ForComplex input [%d][%d] = %f, mat[i][j] = %f, hashmod = %f, "
                //        "vector[j] = %d, nonceMod = %f\n",
                //        i, j, input, mat[i][j], hashMod, vector[j], nonceMod);
                double output = ForComplex(input) * (double)vector[j] * multiplier;
                // printf("ForComplex at [%d][%d] = %f\n", i, j, output);
                product[i] += output;
                // printf("[%d][%d]: %f %f %f %f %f %f\n", i, j, mat[i][j], (double)vector[j], hashMod, nonceMod, input, output);
            }
            else
            {
                double output = mat[i][j] * divider * (double)vector[j];
                product[i] += output;
                // printf("[%d][%d]: %f %f %f\n", i, j, mat[i][j], (double)vector[j], output);
            }
            sw = TransformFactor(product[i]);
        }
    }
    // printf("\n");

    // printf("Product: ");
    // for (int i = 0; i < 63; i++)
    // {
    //     printf("%f, ", product[i]);
    // }
    // printf("%f\n", product[64]);

    for (int i = 0; i < 64; i += 2)
    {
        uint64_t pval = (uint64_t)product[i] + (uint64_t)product[i + 1];
        scaledValues[i / 2] = (uint8_t)(pval & 0xFF);
        // printf("[%u] -> %f + %f -> %ld -> %u\n", i / 2, product[i], product[i + 1], pval, scaledValues[i / 2]);
    }

    // printf("Final pass: [");
    for (int i = 0; i < 32; i++)
    {
        result[i] = hashBytes[i] ^ scaledValues[i];
        // printf("%d, ", result[i]);
    }
    // printf("]\n");
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, result, DOMAIN_HASH_SIZE);
    blake3_hasher_finalize(&hasher, output, DOMAIN_HASH_SIZE);
}

void CalculateProofOfWorkValue(State *state, uint8_t *result)
{

    blake3_hasher hasher;
    uint8_t firstPass[DOMAIN_HASH_SIZE];
    uint8_t lastPass[DOMAIN_HASH_SIZE];
    uint8_t zeroes[DOMAIN_HASH_SIZE] = {0};

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, state->PrevHeader, DOMAIN_HASH_SIZE);
    // state->Timestamp = le64dec(state->Timestamp);
    blake3_hasher_update(&hasher, &state->Timestamp, sizeof(state->Timestamp));
    blake3_hasher_update(&hasher, zeroes, DOMAIN_HASH_SIZE);
    // state->Nonce = le64dec(state->Nonce);
    blake3_hasher_update(&hasher, &state->Nonce, sizeof(state->Nonce));
    blake3_hasher_finalize(&hasher, firstPass, DOMAIN_HASH_SIZE);
    // printf("First pass: %s\n", encodeHex(firstPass, DOMAIN_HASH_SIZE));

    // Perform Hoohash matrix multiplication
    HoohashMatrixMultiplication(state->mat, firstPass, lastPass, state->Nonce);

    // Copy lastPass to result if needed
    memcpy(result, lastPass, DOMAIN_HASH_SIZE);
}

void miningAlgorithm(State *state, uint8_t *result)
{
    CalculateProofOfWorkValue(state, result);
    // Print the actual output as a hexadecimal string
    // printf("Actual Output (Hex): %s\n", encodeHex(result, DOMAIN_HASH_SIZE));
}