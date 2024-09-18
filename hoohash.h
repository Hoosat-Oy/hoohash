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

#ifndef HOOHASH_H
#define HOOHASH_H

#include <stdint.h>
#include <stddef.h>
#include "bigint.h"

// Define the size of the hash domain
#define DOMAIN_HASH_SIZE 32

// Define the epsilon value for numerical stability in calculations
#define EPS 1e-9

// Define the value of PI
#define PI 3.14159265358979323846

// Define the State structure used in the mining algorithm
typedef struct {
    uint16_t mat[64][64];
    int64_t Timestamp;
    uint64_t Nonce;
    uint8_t Target[DOMAIN_HASH_SIZE];
    uint8_t prePowHash[DOMAIN_HASH_SIZE];
} State;

// Define the xoshiro state structure used in the random number generator
typedef struct {
    uint64_t s0;
    uint64_t s1;
    uint64_t s2;
    uint64_t s3;
} xoshiro_state;

// Function to convert a byte array to BigInt
BigInt toBig(uint8_t *hash, size_t hash_len);

// Function to encode a byte array into a hexadecimal string
char* encodeHex(const uint8_t *bytes, size_t length);

// Function to decode a hexadecimal string into a byte array
uint8_t* decodeHex(const char *hexStr, size_t* outSize);

// Function to split a 32-byte array into four 64-bit integers
void split_uint8_array_to_uint64(const uint8_t arr[32], uint64_t out[4]);

// Function to initialize the xoshiro state from a byte array
static inline xoshiro_state xoshiro_init(const uint8_t* bytes);

// Function to generate a 64-bit integer from the xoshiro state
static inline uint64_t xoshiro_gen(xoshiro_state* x);

// Function to compute the rank of a matrix
int computeHoohashRank(uint16_t mat[64][64]);

// Function to generate the Hoohash matrix
void generateHoohashMatrix(uint8_t *hash, uint16_t mat[64][64]);

// Function to perform matrix multiplication with the Hoohash matrix
void HoohashMatrixMultiplication(uint16_t mat[64][64], const uint8_t *hashBytes, uint8_t* output);

// Function to calculate the proof of work value
void CalculateProofOfWorkValue(State *state, uint8_t* result);

// Function to run the mining algorithm
void miningAlgorithm(State* state);

// Function to run test data for the mining algorithm
void runTestData();

#endif // HOOHASH_H