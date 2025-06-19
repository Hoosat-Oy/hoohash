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

#include "bigint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to initialize a BigInt
void BigInt_init(BigInt *bigint, size_t size)
{
    bigint->digits = (unsigned char *)malloc(size);
    if (bigint->digits == NULL)
    {
        perror("Failed to allocate memory for BigInt");
        exit(EXIT_FAILURE);
    }
    memset(bigint->digits, 0, size);
    bigint->size = size;
}

// Function to free a BigInt
void BigInt_free(BigInt *bigint)
{
    free(bigint->digits);
    bigint->digits = NULL;
    bigint->size = 0;
}

// Function to print a BigInt
void BigInt_print(const BigInt *bigint)
{
    for (size_t i = 0; i < bigint->size; i++)
    {
        printf("%d", bigint->digits[i]);
    }
    printf("\n");
}