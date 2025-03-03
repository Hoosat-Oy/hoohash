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
#include <float.h>
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

static inline xoshiro_state xoshiro_init(const uint8_t *bytes)
{
    xoshiro_state state;
    // Copy the 32 bytes (256 bits) from hashArray into the state variables
    state.s0 = *(uint64_t *)(&bytes[0]);
    state.s1 = *(uint64_t *)(&bytes[8]);
    state.s2 = *(uint64_t *)(&bytes[16]);
    state.s3 = *(uint64_t *)(&bytes[24]);
    return state;
}

static inline uint64_t rotl64(const uint64_t x, int k)
{
    return (x << k) | (x >> (64 - k));
}

static inline uint64_t xoshiro_gen(xoshiro_state *x)
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
float MediumComplexNonLinear(float x)
{
    return exp(sin(x) + cos(x));
}

float IntermediateComplexNonLinear(float x)
{
    if (x == PI / 2 || x == 3 * PI / 2)
    {
        return 0; // Avoid singularity
    }
    return sin(x) * cos(x) * tan(x);
}

float HighComplexNonLinear(float x)
{
    return exp(x) * log(x + 1);
}

float ComplexNonLinear(float x)
{
    float transformFactor = fmod(x, 4) / 4;
    if (x < 1)
    {
        if (transformFactor < 0.25)
        {
            return MediumComplexNonLinear(x + (1 + transformFactor));
        }
        else if (transformFactor < 0.5)
        {
            return MediumComplexNonLinear(x - (1 + transformFactor));
        }
        else if (transformFactor < 0.75)
        {
            return MediumComplexNonLinear(x * (1 + transformFactor));
        }
        else
        {
            return MediumComplexNonLinear(x / (1 + transformFactor));
        }
    }
    else if (x < 10)
    {
        if (transformFactor < 0.25)
        {
            return IntermediateComplexNonLinear(x + (1 + transformFactor));
        }
        else if (transformFactor < 0.5)
        {
            return IntermediateComplexNonLinear(x - (1 + transformFactor));
        }
        else if (transformFactor < 0.75)
        {
            return IntermediateComplexNonLinear(x * (1 + transformFactor));
        }
        else
        {
            return IntermediateComplexNonLinear(x / (1 + transformFactor));
        }
    }
    else
    {
        if (transformFactor < 0.25)
        {
            return HighComplexNonLinear(x + (1 + transformFactor));
        }
        else if (transformFactor < 0.5)
        {
            return HighComplexNonLinear(x - (1 + transformFactor));
        }
        else if (transformFactor < 0.75)
        {
            return HighComplexNonLinear(x * (1 + transformFactor));
        }
        else
        {
            return HighComplexNonLinear(x / (1 + transformFactor));
        }
    }
}

// These matter to precision.
#define COMPLEX_OUTPUT_CLAMP 100000
#define COMPLEX_INPUT_CLAMP_START_POINT 64
#define PRODUCT_VALUE_SCALE_MULTIPLIER 0.00001

int complexRounds = 0;

float ForComplex(float forComplex)
{
    float complex;
    complex = ComplexNonLinear(forComplex);
    while (complex >= COMPLEX_OUTPUT_CLAMP)
    {
        complexRounds++;
        forComplex = forComplex * 0.1;
        complex = ComplexNonLinear(forComplex);
    }
    return complex;
}

void generateHoohashMatrix(uint8_t *hash, float mat[64][64])
{
    xoshiro_state state = xoshiro_init(hash);
    float normalize = 100000000.f;
    for (int i = 0; i < 64; i++)
    {
        for (int j = 0; j < 64; j++)
        {
            float matrix_val;
            uint64_t val = xoshiro_gen(&state);
            uint32_t lower_4_bytes = val & 0xFFFFFFFF;
            matrix_val = (float)(lower_4_bytes) / (float)UINT32_MAX * (normalize * 2) - normalize;
            // printf("mat[%d][%d]: %f\n", i, j, matrix_val);
            mat[i][j] = matrix_val;
        }
    }
    printf("Matrix: [");
    for (int i = 0; i < 64; i++)
    {
        printf("%f ", mat[0][i]);
    }
    printf("]\n");
}

void HoohashMatrixMultiplication(float mat[64][64], const uint8_t *hashBytes, uint8_t *output)
{
    uint8_t vector[64] = {0};
    float product[64] = {0};

    // Populate the vector with floating-point values
    for (int i = 0; i < 32; i++)
    {
        vector[2 * i] = hashBytes[i] >> 4;
        vector[2 * i + 1] = hashBytes[i] & 0x0F;
    }
    // printf("Matrix[0]: ");
    // for (int i = 0; i < 64; i++)
    // {
    //     printf("%f, ", mat[0][i]);
    // }
    // printf("\n");
    printf("Vector: [");
    for (int i = 0; i < 64; i++)
    {
        printf("%d ", vector[i]);
    }
    printf("]\n");

    // Matrix-vector multiplication with floating point operations
    int forComplexCalls = 0;
    complexRounds = 0;
    // printf("For Complex: ");
    for (int i = 0; i < 64; i++)
    {
        for (int j = 0; j < 64; j++)
        {
            int sw = (((i * vector[j]) * (j * vector[i]))) % 128;
            // printf("(%d, %d), (%d, %d) sw: %d\n", i, j, vector[i], vector[j], sw);
            switch (sw)
            {
            case 0:
                float transformFactor = fmod(mat[i][j] * PRODUCT_VALUE_SCALE_MULTIPLIER, 1);
                transformFactor = (transformFactor < 0) ? transformFactor + 1.0f : transformFactor;
                // printf("TansformFactor %f\n", transformFactor);
                if (transformFactor < 0.25)
                {

                    forComplexCalls++;
                    product[i] += ForComplex(mat[i][j] * vector[j]);
                    break;
                }
                else if (transformFactor < 0.5)
                {

                    forComplexCalls++;
                    product[i] += ForComplex(mat[i][j] * vector[i]);
                    break;
                }
                else if (transformFactor < 0.75)
                {

                    forComplexCalls++;
                    product[i] += ForComplex(mat[j][i] * vector[j]);
                    break;
                }
                else
                {

                    forComplexCalls++;
                    product[i] += ForComplex(mat[j][i] * vector[i]);
                    break;
                }
            case 1:
            case 67:
                product[i] += mat[i][j] + mat[j][i];
                break;
            case 2:
            case 68:
                if (mat[i][j] > mat[j][i])
                {
                    product[i] += mat[i][j] - mat[j][i];
                }
                else
                {
                    product[i] += mat[j][i] - mat[i][j];
                }
                break;
            case 3:
            case 69:
                product[i] += mat[i][j] + vector[j];
                break;
            case 4:
            case 70:
                product[i] += (mat[j][i] - vector[j]) * vector[j];
                break;
            case 5:
            case 71:
                if (vector[j] != 0)
                {
                    product[i] += mat[i][j] / vector[j];
                }
                else
                {
                    product[i] += mat[i][j] / 1.0f; // Safeguard against division by zero.
                }
                break;
            case 6:
            case 72:
                product[i] += mat[i][j];
                break;
            case 7:
            case 73:
                product[i] += mat[j][i];
                break;
            case 8:
            case 74:
                product[i] += (mat[i][j] - vector[i]) * vector[j];
                break;
            case 9:
            case 75:
                product[i] += vector[i];
                break;
            case 10:
            case 76:
                product[i] += vector[j];
                break;
            case 11:
            case 77:
                product[i] -= vector[j];
                break;
            case 12:
            case 78:
                product[i] += (mat[i][j] - vector[j]) * vector[i];
                break;
            case 13:
            case 79:
                product[i] -= vector[i];
                break;
            case 14:
            case 80:
                product[i] -= mat[j][i];
                break;
            case 15:
            case 16:
            case 81:
                product[i] += mat[i][j] - vector[j];
                break;
            case 18:
            case 82:
                product[i] -= mat[i][j];
                break;
            case 19:
            case 83:
                product[i] -= (mat[i][j] - vector[i]) * vector[j];
                break;
            case 20:
            case 84:
                product[i] -= (mat[j][i] - vector[i]) * vector[j];
                break;
            case 21:
            case 85:
                product[i] -= (mat[i][j] - vector[j]) * vector[i];
                break;
            case 22:
            case 86:
                product[i] -= (mat[j][i] - vector[j]) * vector[i];
                break;
            case 23:
            case 87:
                product[i] += mat[i][j] - vector[i];
                break;
            case 24:
            case 88:
                product[i] += mat[j][i] - vector[i];
                break;
            case 25:
            case 89:
                product[i] -= (mat[j][i] * vector[j]) + vector[i];
                break;
            case 26:
            case 90:
                product[i] += mat[i][j] * vector[j] * PRODUCT_VALUE_SCALE_MULTIPLIER;
                break;
            case 27:
            case 91:
                if (mat[i][j] > mat[j][i])
                {
                    product[i] += mat[i][j] / mat[j][i];
                }
                else
                {
                    product[i] += mat[j][i] / mat[i][j];
                }
                break;
            case 28:
            case 92:
                product[i] += mat[i][j] + vector[i];
                break;
            case 29:
            case 93:
                product[i] += mat[j][i] + vector[i];
                break;
            case 30:
            case 94:
            case 31:
            case 95:
                product[i] -= (mat[j][i] * vector[i]) + vector[j];
                break;
            case 32:
            case 33:
            case 96:
                product[i] += (mat[i][j] * vector[j] * PRODUCT_VALUE_SCALE_MULTIPLIER) + vector[i];
                break;
            case 34:
            case 97:
                product[i] += (mat[i][j] * vector[j] * PRODUCT_VALUE_SCALE_MULTIPLIER) - vector[i];
                break;
            case 35:
            case 98:
                product[i] += (mat[i][j] * vector[i] * PRODUCT_VALUE_SCALE_MULTIPLIER) - vector[j];
                break;
            case 36:
            case 99:
                product[i] += (mat[i][j] * vector[i] * PRODUCT_VALUE_SCALE_MULTIPLIER) + vector[j];
                break;
            case 37:
            case 100:
                product[i] += (mat[j][i] * vector[i] * PRODUCT_VALUE_SCALE_MULTIPLIER) + vector[j];
                break;
            case 38:
            case 101:
                product[i] += (mat[j][i] * vector[i] * PRODUCT_VALUE_SCALE_MULTIPLIER) - vector[j];
                break;
            case 39:
            case 102:
                product[i] += (mat[j][i] * vector[j] * PRODUCT_VALUE_SCALE_MULTIPLIER) + vector[i];
                break;
            case 40:
            case 103:
                product[i] += (mat[j][i] * vector[j] * PRODUCT_VALUE_SCALE_MULTIPLIER) - vector[i];
                break;
            case 41:
            case 104:
                product[i] -= (mat[i][j] * vector[j] * PRODUCT_VALUE_SCALE_MULTIPLIER) + vector[i];
                break;
            case 42:
            case 105:
                product[i] -= (mat[i][j] * vector[j] * PRODUCT_VALUE_SCALE_MULTIPLIER) - vector[i];
                break;
            case 43:
            case 106:
                product[i] -= (mat[i][j] * vector[i] * PRODUCT_VALUE_SCALE_MULTIPLIER) - vector[j];
                break;
            case 44:
            case 107:
                product[i] -= (mat[i][j] * vector[i] * PRODUCT_VALUE_SCALE_MULTIPLIER) + vector[j];
                break;
            case 45:
            case 108:
                product[i] -= (mat[j][i] * vector[i] * PRODUCT_VALUE_SCALE_MULTIPLIER) + vector[j];
                break;
            case 46:
            case 109:
                product[i] -= (mat[j][i] * vector[i] * PRODUCT_VALUE_SCALE_MULTIPLIER) - vector[j];
                break;
            case 47:
            case 110:
                product[i] -= (mat[j][i] * vector[j] * PRODUCT_VALUE_SCALE_MULTIPLIER) + vector[i];
                break;
            case 48:
            case 112:
                product[i] -= (mat[j][i] * vector[j] * PRODUCT_VALUE_SCALE_MULTIPLIER) - vector[i];
                break;
            case 49:
            case 113:
                product[i] += vector[j] % vector[i];
                break;
            case 50:
            case 114:
                product[i] += vector[i] % vector[j];
                break;
            case 51:
            case 115:
                product[i] -= vector[j] % vector[i];
                break;
            case 52:
            case 116:
                product[i] -= vector[i] % vector[j];
                break;
            case 53:
            case 117:
                product[i] += vector[i] & vector[j];
                break;
            case 54:
            case 118:
                product[i] -= vector[i] & vector[j];
                break;
            case 56:
            case 119:
                product[i] += vector[i] | vector[j];
                break;
            case 57:
            case 120:
                product[i] -= vector[i] | vector[j];
                break;
            case 58:
            case 121:
                product[i] += mat[i][j] * (vector[j] % vector[i]) * PRODUCT_VALUE_SCALE_MULTIPLIER;
                break;
            case 59:
            case 122:
                product[i] += mat[i][j] * (vector[i] % vector[j]) * PRODUCT_VALUE_SCALE_MULTIPLIER;
                break;
            case 60:
            case 123:
                product[i] -= mat[i][j] * (vector[j] % vector[i]) * PRODUCT_VALUE_SCALE_MULTIPLIER;
                break;
            case 61:
            case 124:
                product[i] -= mat[i][j] * (vector[i] % vector[j]) * PRODUCT_VALUE_SCALE_MULTIPLIER;
                break;
            case 63:
            case 125:
                product[i] += mat[i][j] * (vector[i] & vector[j]) * PRODUCT_VALUE_SCALE_MULTIPLIER;
                break;
            case 64:
            case 126:
                product[i] -= mat[i][j] * (vector[i] & vector[j]) * PRODUCT_VALUE_SCALE_MULTIPLIER;
                break;
            case 65:
            case 127:
                product[i] += mat[i][j] * (vector[i] | vector[j]) * PRODUCT_VALUE_SCALE_MULTIPLIER;
                break;
            case 66:
            case 128:
                product[i] -= mat[i][j] * (vector[i] | vector[j]) * PRODUCT_VALUE_SCALE_MULTIPLIER;
                break;
            default:
                product[i] += mat[i][j] * vector[j] * PRODUCT_VALUE_SCALE_MULTIPLIER;
                break;
            }
        }
    }
    printf("ComplexRounds %d\n", complexRounds);
    printf("ForComplex called! %d\n", forComplexCalls);
    printf("\n");
    printf("Product: [");
    for (int i = 0; i < 64; i++)
    {
        printf("%f, ", product[i]);
    }
    printf("]\n");

    // XOR the hash with product values, before using as input for final blake3 pass.
    printf("Final pass: [");
    uint8_t res[32] = {0};
    // combine and scale product values
    uint8_t scaledValues[32] = {0};
    for (int i = 0; i < 64; i += 2)
    {
        scaledValues[i / 2] = (uint8_t)((product[i] + product[i + 1]) * PRODUCT_VALUE_SCALE_MULTIPLIER);
    }
    // Xor with prehash
    for (int i = 0; i < 32; i++)
    {
        res[i] = hashBytes[i] ^ scaledValues[i];
        printf("%d ", res[i]);
    }
    printf("]\n");
    // Hash again using BLAKE3
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, res, DOMAIN_HASH_SIZE);
    blake3_hasher_finalize(&hasher, output, DOMAIN_HASH_SIZE);
}

void CalculateProofOfWorkValue(State *state, uint8_t *result)
{
    // PRE_POW_HASH || LE_TIME || 32 zero byte padding || LE_NONCE
    blake3_hasher hasher;
    uint8_t firstPass[DOMAIN_HASH_SIZE];
    uint8_t lastPass[DOMAIN_HASH_SIZE];
    uint8_t zeroes[DOMAIN_HASH_SIZE] = {0};

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, state->prePowHash, DOMAIN_HASH_SIZE);
    // state->Timestamp = le64dec(state->Timestamp);
    blake3_hasher_update(&hasher, &state->Timestamp, sizeof(state->Timestamp));
    blake3_hasher_update(&hasher, zeroes, DOMAIN_HASH_SIZE);
    // state->Nonce = le64dec(state->Nonce);
    blake3_hasher_update(&hasher, &state->Nonce, sizeof(state->Nonce));
    blake3_hasher_finalize(&hasher, firstPass, DOMAIN_HASH_SIZE);
    // printf("First pass: %s\n", encodeHex(firstPass, DOMAIN_HASH_SIZE));

    // Perform Hoohash matrix multiplication
    HoohashMatrixMultiplication(state->mat, firstPass, lastPass);

    // Copy lastPass to result if needed
    memcpy(result, lastPass, DOMAIN_HASH_SIZE);
}