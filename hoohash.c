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
           case FE_TONEAREST:  printf ("FE_TONEAREST");  break;
           case FE_DOWNWARD:   printf ("FE_DOWNWARD");   break;
           case FE_UPWARD:     printf ("FE_UPWARD");     break;
           case FE_TOWARDZERO: printf ("FE_TOWARDZERO"); break;
           default:            printf ("unknown");
    };
    printf("\n");
}

uint8_t* to_little_endian_uint8_t_pointer(const uint8_t *value, size_t size) {
    // Allocate memory for the result
    uint8_t *little_endian_value = (uint8_t*)malloc(size);
    if (little_endian_value == NULL) {
        return NULL; // Memory allocation failed
    }

    #if __BYTE_ORDER == __LITTLE_ENDIAN
    // If the system is already little-endian, copy the value as is
    memcpy(little_endian_value, value, size);
    #else
    // If the system is big-endian, we need to reverse the byte order
    for (size_t i = 0; i < size; i++) {
        little_endian_value[i] = value[size - 1 - i];
    }
    #endif

    return little_endian_value;
}

uint8_t* to_big_endian_uint8_t_pointer(const uint8_t *value, size_t size) {
    // Allocate memory for the result
    uint8_t *big_endian_value = (uint8_t*)malloc(size);
    if (big_endian_value == NULL) {
        return NULL; // Memory allocation failed
    }

    #if __BYTE_ORDER == __BIG_ENDIAN
    // If the system is already big-endian, copy the value as is
    memcpy(big_endian_value, value, size);
    #else
    // If the system is little-endian, we need to reverse the byte order
    for (size_t i = 0; i < size; i++) {
        big_endian_value[i] = value[size - 1 - i];
    }
    #endif

    return big_endian_value;
}

// Function to convert a byte array to BigInt
BigInt toBig(uint8_t *hash, size_t hash_len) {
    BigInt bigint;
    BigInt_init(&bigint, hash_len);
    printf("Before Big endian: %s\n", hash);
    hash = to_big_endian_uint8_t_pointer(hash, hash_len);
    printf("Big endian: %s\n", hash);
    memcpy(bigint.digits, hash, hash_len);
    return bigint;
}

char* encodeHex(const uint8_t *bytes, size_t length) {
    // Each byte is represented by 2 hex characters, plus 1 for the null terminator
    char* hexStr = (char*)malloc(length * 2 + 1);
    if (hexStr == NULL) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < length; i++) {
        snprintf(hexStr + i * 2, 3, "%02x", bytes[i]);
    }
    return hexStr;
}

uint8_t* decodeHex(const char *hexStr, size_t* outSize) {
    size_t len = strlen(hexStr);
    if (len % 2 != 0) {
        fprintf(stderr, "Invalid hex string length.\n");
        return NULL;
    }

    *outSize = len / 2;
    uint8_t* bytes = (uint8_t*)malloc(*outSize);
    if (bytes == NULL) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < *outSize; ++i) {
        char high = hexStr[2 * i];
        char low = hexStr[2 * i + 1];
        bytes[i] = (uint8_t)(((high >= '0' && high <= '9') ? high - '0' : high - 'a' + 10) << 4 |
                             ((low >= '0' && low <= '9') ? low - '0' : low - 'a' + 10));
    }

    return bytes;
}

void split_uint8_array_to_uint64(const uint8_t arr[32], uint64_t out[4]) {
    for (int i = 0; i < 4; i++) {
        out[i] = 0;
        for (int j = 0; j < 8; j++) {
            out[i] |= (uint64_t)arr[i * 8 + j] << (56 - 8 * j);
        }
    }
}


static inline xoshiro_state xoshiro_init(const uint8_t* bytes) {
    xoshiro_state state;
    // Copy the 32 bytes (256 bits) from hashArray into the state variables
    state.s0 = *(uint64_t*)(&bytes[0]);
    state.s1 = *(uint64_t*)(&bytes[8]);
    state.s2 = *(uint64_t*)(&bytes[16]);
    state.s3 = *(uint64_t*)(&bytes[24]);
    return state;
}

static inline uint64_t rotl64(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static inline uint64_t xoshiro_gen(xoshiro_state* x) {
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
float MediumComplexNonLinear(float x) {
    return exp(sin(x) + cos(x));
}

float IntermediateComplexNonLinear(float x) {
    if (x == PI / 2 || x == 3 * PI / 2) {
        return 0; // Avoid singularity
    }
    return sin(x) * cos(x) * tan(x);
}

float HighComplexNonLinear(float x) {
    return exp(x) * log(x + 1);
}

float ComplexNonLinear(float x) {
    float transformFactor = fmod(x, 4) / 4;
    if (x < 1) {
        if (transformFactor < 0.25) {
            return MediumComplexNonLinear(x + (1 + transformFactor));
        } else if (transformFactor < 0.5) {
            return MediumComplexNonLinear(x - (1 + transformFactor));
        } else if (transformFactor < 0.75) {
            return MediumComplexNonLinear(x * (1 + transformFactor));
        } else {
            return MediumComplexNonLinear(x / (1 + transformFactor));
        }
    } else if (x < 10) {
        if (transformFactor < 0.25) {
            return IntermediateComplexNonLinear(x + (1 + transformFactor));
        } else if (transformFactor < 0.5) {
            return IntermediateComplexNonLinear(x - (1 + transformFactor));
        } else if (transformFactor < 0.75) {
            return IntermediateComplexNonLinear(x * (1 + transformFactor));
        } else {
            return IntermediateComplexNonLinear(x / (1 + transformFactor));
        }
    } else {
        if (transformFactor < 0.25) {
            return HighComplexNonLinear(x + (1 + transformFactor));
        } else if (transformFactor < 0.5) {
            return HighComplexNonLinear(x - (1 + transformFactor));
        } else if (transformFactor < 0.75) {
            return HighComplexNonLinear(x * (1 + transformFactor));
        } else {
            return HighComplexNonLinear(x / (1 + transformFactor));
        }
    }
}

int computeHoohashRank(uint16_t mat[64][64]) {
    float B[64][64];
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 64; j++) {
            B[i][j] = mat[i][j] + ComplexNonLinear(mat[i][j]);
        }
    }
    int rank = 0;
    int rowSelected[64] = {0};
    for (int i = 0; i < 64; i++) {
        int j;
        for (j = 0; j < 64; j++) {
            if (!rowSelected[j] && fabs(B[j][i]) > EPS) {
                break;
            }
        }
        if (j != 64) {
            rank++;
            rowSelected[j] = 1;
            for (int p = i + 1; p < 64; p++) {
                B[j][p] /= B[j][i];
            }
            for (int k = 0; k < 64; k++) {
                if (k != j && fabs(B[k][i]) > EPS) {
                    for (int p = i + 1; p < 64; p++) {
                        B[k][p] -= B[j][p] * B[k][i];
                    }
                }
            }
        }
    }
    return rank;
}

void generateHoohashMatrix(uint8_t *hash, uint16_t mat[64][64]) {
    xoshiro_state state = xoshiro_init(hash);
    // printf("state.s0 0x%016llX\n", state.s0);
    // printf("state.s1 0x%016llX\n", state.s1);
    // printf("state.s2 0x%016llX\n", state.s2);
    // printf("state.s3 0x%016llX\n", state.s3);
    for (;;) {
        for (int i = 0; i < 64; i++) {
            for (int j = 0; j < 64; j += 16) {
                uint64_t val = xoshiro_gen(&state);
                for (int shift = 0; shift < 16; ++shift) {
                    mat[i][j + shift] = (val >> (4*shift)) & 0x0F;
                }
            }
        }
        int rank = computeHoohashRank(mat);
        if (rank == 64) {
            return;
        }
    }
}

void HoohashMatrixMultiplication(uint16_t mat[64][64], const uint8_t *hashBytes, uint8_t* output) {
    float vector[64] = {0};
    float product[64] = {0};
    uint8_t res[32] = {0};

    // Populate the vector with floating-point values
    for (int i = 0; i < 32; i++) {
        vector[2 * i] = (float)(hashBytes[i] >> 4);
        vector[2 * i + 1] = (float)(hashBytes[i] & 0x0F);
    }
    
    printf("Vector: ");
    for (int i = 0; i < 64; i++) {
        printf("%d, ", vector[i]);
    }
    printf("\n");

    // Matrix-vector multiplication with floating point operations
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 64; j++) {
            float forComplex = (float)mat[i][j] * vector[j];
            while (forComplex > 16) {
                forComplex = forComplex * 0.1;
            }
            // Transform Matrix values with complex non-linear equations and sum into product.
            product[i] += ComplexNonLinear(forComplex);
        }
    }
    printf("Product: ");
    for (int i = 0; i < 64; i++) {
        printf("%f ", product[i]);
    }
    printf("\n");

    // Convert product back to uint16 and then to byte array
    printf("Hi/Low: ");
    for (int i = 0; i < 32; i++) 
    {
        uint64_t high = product[2 * i] * 0.00000001;
        uint64_t low = product[2 * i + 1] * 0.00000001;
        printf("%d - %d, ", high, low);
		// Combine high and low into a single byte
		uint8_t combined = (high ^ low) & 0xFF;
        res[i] = hashBytes[i] ^ combined;
    }
    printf("\n");
    printf("Res: ");
    for (int i = 0; i < 32; i++) {
        printf("%d,", res[i]);
    }
    printf("\n");

    // Hash again using BLAKE3
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, res, DOMAIN_HASH_SIZE);
    blake3_hasher_finalize(&hasher, output, DOMAIN_HASH_SIZE);
}

void CalculateProofOfWorkValue(State *state, uint8_t* result) {
    // PRE_POW_HASH || LE_TIME || 32 zero byte padding || LE_NONCE
    blake3_hasher hasher;
    uint8_t firstPass[DOMAIN_HASH_SIZE];
    uint8_t lastPass[DOMAIN_HASH_SIZE];
    uint8_t zeroes[DOMAIN_HASH_SIZE] = {0};

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, state->prePowHash, DOMAIN_HASH_SIZE);
    //state->Timestamp = le64dec(state->Timestamp);
    blake3_hasher_update(&hasher, &state->Timestamp, sizeof(state->Timestamp));
    blake3_hasher_update(&hasher, zeroes, DOMAIN_HASH_SIZE);
    //state->Nonce = le64dec(state->Nonce);
    blake3_hasher_update(&hasher, &state->Nonce, sizeof(state->Nonce));
    blake3_hasher_finalize(&hasher, firstPass, DOMAIN_HASH_SIZE);
    //printf("First pass: %s\n", encodeHex(firstPass, DOMAIN_HASH_SIZE));

    // Perform Hoohash matrix multiplication
    HoohashMatrixMultiplication(state->mat, firstPass, lastPass);

    // Copy lastPass to result if needed
    memcpy(result, lastPass, DOMAIN_HASH_SIZE);
}

void miningAlgorithm(State* state) {
    uint8_t result[DOMAIN_HASH_SIZE];
    CalculateProofOfWorkValue(state, result);
    // Print the actual output as a hexadecimal string
    printf("Actual Output (Hex): %s\n", encodeHex(result, DOMAIN_HASH_SIZE));
}

void runTestData() {
    State state;
    {
        printf("-------------------------------------------------------------------------------------\n");
        printf("Test Case Blake3:\n");
        uint8_t bytes[DOMAIN_HASH_SIZE] = {
          0xeb, 0xe6, 0xa6, 0xf3, 0xa5, 0xd5, 0xf7, 0xd8, 
          0x7e, 0x5d, 0x19, 0x0f, 0xa5, 0x93, 0x67, 0xb5, 
          0x29, 0x04, 0x31, 0x6d, 0xbd, 0xaa, 0x63, 0x9f, 
          0xb8, 0x7f, 0xbf, 0xe7, 0x6e, 0x19, 0x43, 0x42
        };
        printf("Input bytes: %s\n", encodeHex(bytes, DOMAIN_HASH_SIZE));
        uint8_t output[DOMAIN_HASH_SIZE];
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, bytes, DOMAIN_HASH_SIZE);
        blake3_hasher_finalize(&hasher, output, DOMAIN_HASH_SIZE);
        printf("Blake3 hash: %s\n", encodeHex(output, DOMAIN_HASH_SIZE));
    }
    {
        for(int i = 0; i < 5; i++) {
            printf("-------------------------------------------------------------------------------------\n");
            uint8_t prePowHash[DOMAIN_HASH_SIZE] = {
                0xa4, 0x9d, 0xbc, 0x7d, 0x44, 0xae, 0x83, 0x25, 0x38, 0x23, 0x59, 0x2f, 0xd3, 0x88, 0xf2, 0x19, 0xf3, 0xcb, 0x83, 0x63, 0x9d, 0x54, 0xc9, 0xe4, 0xc3, 0x15, 0x4d, 0xb3, 0x6f, 0x2b, 0x51, 0x57
            };
            size_t size;
            printf("Test Case :\n");
            printf("Input prePowHash: %s\n", encodeHex(prePowHash, DOMAIN_HASH_SIZE));
            memcpy(state.prePowHash, prePowHash, DOMAIN_HASH_SIZE);
            state.Timestamp = 1725374568455;
            state.Nonce = i;
            //printf("Input Timestamp: %lld\n", state.Timestamp);
            //printf("Input Nonce: %llu\n", state.Nonce);
            generateHoohashMatrix(prePowHash, state.mat);
            miningAlgorithm(&state);
        }
        for(int i = 0; i < 5; i++) {
            printf("-------------------------------------------------------------------------------------\n");
            uint8_t prePowHash[DOMAIN_HASH_SIZE] = {
                0xc6, 0x34, 0x2b, 0xcd, 0xf1, 0xe7, 0xae, 0xe5, 0x31, 0xc4, 0x2c, 0xf9, 0xd2, 0xe5, 0xaa, 0xfe, 0x59, 0x8d, 0x39, 0xfe, 0x4c, 0xdc, 0x22, 0x6c, 0x45, 0xbc, 0xc9, 0x53, 0xfe, 0xf3, 0x75, 0xff
            };
            size_t size;
            printf("Test Case :\n");
            printf("Input prePowHash: %s\n", encodeHex(prePowHash, DOMAIN_HASH_SIZE));
            memcpy(state.prePowHash, prePowHash, DOMAIN_HASH_SIZE);
            state.Timestamp = 1725374568455;
            state.Nonce = i;
            printf("Input Timestamp: %lld\n", state.Timestamp);
            printf("Input Nonce: %llu\n", state.Nonce);
            generateHoohashMatrix(prePowHash, state.mat);
            miningAlgorithm(&state);
        }
        for(int i = 0; i < 5; i++) {
            printf("-------------------------------------------------------------------------------------\n");
            uint8_t prePowHash[DOMAIN_HASH_SIZE] = {
                0xb7, 0xc8, 0xf4, 0x3d, 0x8a, 0x99, 0xae, 0xcd, 0xd3, 0x79, 0x12, 0xc9, 0xad, 0x4f, 0x2e, 0x51, 0xc8, 0x00, 0x9f, 0x7c, 0xe1, 0xcd, 0xf6, 0xe3, 0xbe, 0x27, 0x67, 0x97, 0x2c, 0xc6, 0x8a, 0x1c
            };
            size_t size;
            printf("Test Case :\n");
            printf("Input prePowHash: %s\n", encodeHex(prePowHash, DOMAIN_HASH_SIZE));
            memcpy(state.prePowHash, prePowHash, DOMAIN_HASH_SIZE);
            state.Timestamp = 1725374568455;
            state.Nonce = i;
            printf("Input Timestamp: %lld\n", state.Timestamp);
            printf("Input Nonce: %llu\n", state.Nonce);
            generateHoohashMatrix(prePowHash, state.mat);
            miningAlgorithm(&state);
        }
    }
}
