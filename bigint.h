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

#ifndef BIGINT_H
#define BIGINT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
