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

void printMatrixSummary(double matrix[64][64])
{
    printf("Matrix (first 3x3 elements):\n");
    for (int i = 0; i < 3; i++)
    {
        for (int j = 0; j < 3; j++)
        {
            printf("%.2f ", matrix[i][j]);
        }
        printf("\n");
    }
}

void runTestData()
{
    fesetround(FE_TONEAREST);
    State state;
    uint8_t result[DOMAIN_HASH_SIZE];
    FILE *file = fopen("pow_hashes.txt", "w");
    if (!file)
    {
        printf("Error opening file for writing.\n");
        return;
    }
    // {
    //     printf("-------------------------------------------------------------------------------------\n");
    //     printf("Test Case Blake3:\n");
    //     uint8_t bytes[DOMAIN_HASH_SIZE] = {
    //         0xeb, 0xe6, 0xa6, 0xf3, 0xa5, 0xd5, 0xf7, 0xd8,
    //         0x7e, 0x5d, 0x19, 0x0f, 0xa5, 0x93, 0x67, 0xb5,
    //         0x29, 0x04, 0x31, 0x6d, 0xbd, 0xaa, 0x63, 0x9f,
    //         0xb8, 0x7f, 0xbf, 0xe7, 0x6e, 0x19, 0x43, 0x42};
    //     printf("Input bytes: %s\n", encodeHex(bytes, DOMAIN_HASH_SIZE));
    //     uint8_t output[DOMAIN_HASH_SIZE];
    //     blake3_hasher hasher;
    //     blake3_hasher_init(&hasher);
    //     blake3_hasher_update(&hasher, bytes, DOMAIN_HASH_SIZE);
    //     blake3_hasher_finalize(&hasher, output, DOMAIN_HASH_SIZE);
    //     printf("Blake3 hash: %s\n", encodeHex(output, DOMAIN_HASH_SIZE));
    // }
    {
        printf("-------------------------------------------------------------------------------------\n");
        uint8_t PrevHeader[DOMAIN_HASH_SIZE] = {0xa4, 0x9d, 0xbc, 0x7d, 0x44, 0xae, 0x83, 0x25, 0x38, 0x23, 0x59, 0x2f, 0xd3, 0x88, 0xf2, 0x19, 0xf3, 0xcb, 0x83, 0x63, 0x9d, 0x54, 0xc9, 0xe4, 0xc3, 0x15, 0x4d, 0xb3, 0x6f, 0x2b, 0x51, 0x57};
        printf("Test Case %i:\n", 0);
        printf("Input PrevHeader: %s\n", encodeHex(PrevHeader, DOMAIN_HASH_SIZE));
        memcpy(state.PrevHeader, PrevHeader, DOMAIN_HASH_SIZE);
        state.Timestamp = 1725374568455;
        state.Nonce = 16957671692455988494UL;
        printf("Input Timestamp: %ld\n", state.Timestamp);
        printf("Input Nonce: %lu\n", state.Nonce);
        generateHoohashMatrix(PrevHeader, state.mat);
        printMatrixSummary(state.mat);
        blake3_hasher hasher;
        uint8_t firstPass[DOMAIN_HASH_SIZE];
        uint8_t lastPass[DOMAIN_HASH_SIZE];
        uint8_t zeroes[DOMAIN_HASH_SIZE] = {0};

        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, state.PrevHeader, DOMAIN_HASH_SIZE);
        blake3_hasher_update(&hasher, &state.Timestamp, sizeof(state.Timestamp));
        blake3_hasher_update(&hasher, zeroes, DOMAIN_HASH_SIZE);
        blake3_hasher_update(&hasher, &state.Nonce, sizeof(state.Nonce));
        blake3_hasher_finalize(&hasher, firstPass, DOMAIN_HASH_SIZE);

        printf("First passs (Hex): %s\n", encodeHex(firstPass, DOMAIN_HASH_SIZE));
        // Perform Hoohash matrix multiplication
        HoohashMatrixMultiplication(state.mat, firstPass, lastPass, state.Nonce);

        // Copy lastPass to result if needed
        memcpy(result, lastPass, DOMAIN_HASH_SIZE);
        printf("Actual Output (Hex): %s\n", encodeHex(result, DOMAIN_HASH_SIZE));
    }
    {
        printf("-------------------------------------------------------------------------------------\n");
        uint8_t PrevHeader[DOMAIN_HASH_SIZE] = {0xb7, 0xc8, 0xf4, 0x3d, 0x8a, 0x99, 0xae, 0xcd, 0xd3, 0x79, 0x12, 0xc9, 0xad, 0x4f, 0x2e, 0x51, 0xc8, 0x00, 0x9f, 0x7c, 0xe1, 0xcd, 0xf6, 0xe3, 0xbe, 0x27, 0x67, 0x97, 0x2c, 0xc6, 0x8a, 0x1c};
        printf("Test Case %i:\n", 0);
        printf("Input PrevHeader: %s\n", encodeHex(PrevHeader, DOMAIN_HASH_SIZE));
        memcpy(state.PrevHeader, PrevHeader, DOMAIN_HASH_SIZE);
        state.Timestamp = 1725374568234;
        state.Nonce = 14449448288038978941ULL;
        printf("Input Timestamp: %ld\n", state.Timestamp);
        printf("Input Nonce: %lu\n", state.Nonce);
        generateHoohashMatrix(PrevHeader, state.mat);
        printMatrixSummary(state.mat);
        blake3_hasher hasher;
        uint8_t firstPass[DOMAIN_HASH_SIZE];
        uint8_t lastPass[DOMAIN_HASH_SIZE];
        uint8_t zeroes[DOMAIN_HASH_SIZE] = {0};

        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, state.PrevHeader, DOMAIN_HASH_SIZE);
        blake3_hasher_update(&hasher, &state.Timestamp, sizeof(state.Timestamp));
        blake3_hasher_update(&hasher, zeroes, DOMAIN_HASH_SIZE);
        blake3_hasher_update(&hasher, &state.Nonce, sizeof(state.Nonce));
        blake3_hasher_finalize(&hasher, firstPass, DOMAIN_HASH_SIZE);

        printf("First passs (Hex): %s\n", encodeHex(firstPass, DOMAIN_HASH_SIZE));
        // Perform Hoohash matrix multiplication
        HoohashMatrixMultiplication(state.mat, firstPass, lastPass, state.Nonce);

        // Copy lastPass to result if needed
        memcpy(result, lastPass, DOMAIN_HASH_SIZE);
        printf("Actual Output (Hex): %s\n", encodeHex(result, DOMAIN_HASH_SIZE));
    }

    // for (int i = 0; i < 5; i++)
    // {
    //     printf("-------------------------------------------------------------------------------------\n");
    //     uint8_t PrevHeader[DOMAIN_HASH_SIZE] = {
    //         0xc6, 0x34, 0x2b, 0xcd, 0xf1, 0xe7, 0xae, 0xe5, 0x31, 0xc4, 0x2c, 0xf9, 0xd2, 0xe5, 0xaa, 0xfe, 0x59, 0x8d, 0x39, 0xfe, 0x4c, 0xdc, 0x22, 0x6c, 0x45, 0xbc, 0xc9, 0x53, 0xfe, 0xf3, 0x75, 0xff};
    //     printf("Test Case %i:\n", i);
    //     printf("Input PrevHeader: %s\n", encodeHex(PrevHeader, DOMAIN_HASH_SIZE));
    //     memcpy(state.PrevHeader, PrevHeader, DOMAIN_HASH_SIZE);
    //     state.Timestamp = 1725374568455;
    //     state.Nonce = i;
    //     printf("Input Timestamp: %ld\n", state.Timestamp);
    //     printf("Input Nonce: %lu\n", state.Nonce);
    //     generateHoohashMatrix(PrevHeader, state.mat);
    //     miningAlgorithm(&state, result);
    //     printf("Actual Output (Hex): %s\n", encodeHex(result, DOMAIN_HASH_SIZE));
    // }

    // {
    //     printf("-------------------------------------------------------------------------------------\n");
    //     uint8_t PrevHeader[DOMAIN_HASH_SIZE] = {
    //         0xb7, 0xc8, 0xf4, 0x3d, 0x8a, 0x99, 0xae, 0xcd, 0xd3, 0x79, 0x12, 0xc9, 0xad, 0x4f, 0x2e, 0x51, 0xc8, 0x00, 0x9f, 0x7c, 0xe1, 0xcd, 0xf6, 0xe3, 0xbe, 0x27, 0x67, 0x97, 0x2c, 0xc6, 0x8a, 0x1c};
    //     printf("Test Case %i:\n", 172537456);
    //     printf("Input PrevHeader: %s\n", encodeHex(PrevHeader, DOMAIN_HASH_SIZE));
    //     memcpy(state.PrevHeader, PrevHeader, DOMAIN_HASH_SIZE);
    //     state.Timestamp = 172537456;
    //     state.Nonce = 85;
    //     printf("Input Timestamp: %ld\n", state.Timestamp);
    //     printf("Input Nonce: %lu\n", state.Nonce);
    //     generateHoohashMatrix(PrevHeader, state.mat);
    //     miningAlgorithm(&state, result);
    //     char *resultHex = encodeHex(result, DOMAIN_HASH_SIZE);
    //     printf("Actual Output (Hex): %s\n", encodeHex(result, DOMAIN_HASH_SIZE));
    // }
    // for (int i = 0; i < 1000; i++)
    // {
    //     for (int x = 0; x < 1000; x++)
    //     {
    //         printf("-------------------------------------------------------------------------------------\n");
    //         uint8_t PrevHeader[DOMAIN_HASH_SIZE] = {
    //             0xb7, 0xc8, 0xf4, 0x3d, 0x8a, 0x99, 0xae, 0xcd, 0xd3, 0x79, 0x12, 0xc9, 0xad, 0x4f, 0x2e, 0x51, 0xc8, 0x00, 0x9f, 0x7c, 0xe1, 0xcd, 0xf6, 0xe3, 0xbe, 0x27, 0x67, 0x97, 0x2c, 0xc6, 0x8a, 0x1c};
    //         printf("Test Case %i:\n", i * x);
    //         printf("Input PrevHeader: %s\n", encodeHex(PrevHeader, DOMAIN_HASH_SIZE));
    //         memcpy(state.PrevHeader, PrevHeader, DOMAIN_HASH_SIZE);
    //         state.Timestamp = 172537456 + i;
    //         state.Nonce = x;
    //         printf("Input Timestamp: %ld\n", state.Timestamp);
    //         printf("Input Nonce: %lu\n", state.Nonce);
    //         generateHoohashMatrix(PrevHeader, state.mat);
    //         miningAlgorithm(&state, result);
    //         char *resultHex = encodeHex(result, DOMAIN_HASH_SIZE);
    //         printf("Actual Output (Hex): %s\n", resultHex);
    //         fprintf(file, "%s\n", resultHex);
    //         free(resultHex);
    //     }
    // }
    // {
    //     printf("-------------------------------------------------------------------------------------\n");
    //     uint8_t PrevHeader[DOMAIN_HASH_SIZE] = {
    //         0x82, 0xb1, 0xd1, 0x7c, 0x5e, 0x22, 0x00, 0xa0, 0x56, 0x59, 0x56, 0xb7, 0x11, 0x48, 0x5a, 0x2c, 0xba, 0x6d, 0xa9, 0x09, 0xe5, 0x88, 0x26, 0x15, 0x82, 0xc2, 0xf4, 0x65, 0xec, 0x2e, 0x3d, 0x3f};
    //     printf("Test Case Last:\n");
    //     printf("Input PrevHeader: %s\n", encodeHex(PrevHeader, DOMAIN_HASH_SIZE));
    //     memcpy(state.PrevHeader, PrevHeader, DOMAIN_HASH_SIZE);
    //     state.Timestamp = 1727011258677;
    //     state.Nonce = 7794931619413402210;
    //     printf("Input Timestamp: %ld\n", state.Timestamp);
    //     printf("Input Nonce: %lu\n", state.Nonce);
    //     generateHoohashMatrix(PrevHeader, state.mat);
    //     miningAlgorithm(&state, result);
    //     printf("Actual Output (Hex): %s\n", encodeHex(result, DOMAIN_HASH_SIZE));
    // }
    // {
    //     printf("-------------------------------------------------------------------------------------\n");
    //     uint8_t PrevHeader[DOMAIN_HASH_SIZE] = {
    //         0x00, 0x88, 0x6c, 0xc7, 0x8f, 0xe0, 0x36, 0x6b, 0x00, 0x9c, 0x4c, 0x10, 0xe7, 0x07, 0x4a, 0x5c, 0x00, 0x68, 0x66, 0xeb, 0xe7, 0x25, 0x7f, 0xa5, 0x00, 0x58, 0xd2, 0xdc, 0x6f, 0x16, 0xfc, 0xc4};
    //     printf("Test Case Last:\n");
    //     printf("Input PrevHeader: %s\n", encodeHex(PrevHeader, DOMAIN_HASH_SIZE));
    //     memcpy(state.PrevHeader, PrevHeader, DOMAIN_HASH_SIZE);
    //     state.Timestamp = 1744021604965;
    //     state.Nonce = 350612;
    //     printf("Input Timestamp: %ld\n", state.Timestamp);
    //     printf("Input Nonce: %lu\n", state.Nonce);
    //     generateHoohashMatrix(PrevHeader, state.mat);
    //     miningAlgorithm(&state, result);
    //     printf("Actual Output (Hex): %s\n", encodeHex(result, DOMAIN_HASH_SIZE));
    //     printf("Hoominers hash     : 0008dfab45f7f7626fdb9b4d4ddf590d125905e22beecf1b88291a2dcbd6215b\n");
    // }
}

int main()
{
    runTestData();
}