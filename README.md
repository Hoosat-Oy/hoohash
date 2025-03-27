# Hoohash documentation

Hoohash is novel proof of work hashing algorithm. The primary functionality includes double point arithmetic, blake3 hashing, matrix operations, non-linear transformations.

## License

This software is licensed under the GNU General Public License (GPL) Version 3.0 or later. See the full [license](https://www.gnu.org/licenses/) for details.

- **Author**: Tonto, Toni Lukkaroinen
- **Company**: Hoosat Oy
- **Copyright**: 2024 Hoosat Oy

## Overview

Key components of the project include:

- Complex non-linear transformations
- Hoohash matrix generation and manipulation
- Proof of work generation for blockchain-like applications
- Use of BLAKE3 for cryptographic hashing

## Building the Dynamic Library

To compile the Hoohash dynamic library, simply run:

```bash
make
```

This will generate the shared library `lib-hoohash.so` in the `build` directory.

To clean up the generated files, run:

```bash
make clean
```

Alternatively, if you'd like to manually compile it using GCC, you can use the following command:

```bash
gcc -fPIC -shared -o lib-hoohash.so hoohash.c bigint.c -lm -lblake3
```

This will create the shared library lib-hoohash.so in the current directory, linking the math and BLAKE3 libraries.

## Running Tests

To build and run the tests, first compile the test executable with:

```bash
make test
```

This will create the `build/main-test` executable, which can be run as follows:

```bash
./build/main-test
```

## Key Functions

### 1. `generateHoohashMatrix`

Generates a 64x64 matrix based on random values derived from a given hash input using the xoshiro PRNG. The matrix is populated and processed until its rank reaches 64.

### 3. `CalculateProofOfWorkValue`

Generates a proof-of-work value using a combination of the Hoohash matrix multiplication and a series of hashing steps. The function combines multiple inputs, including a pre-computed hash, timestamp, and nonce, to compute a final result.

## Dependencies

- **BLAKE3**: The project uses the BLAKE3 cryptographic hashing algorithm for high-speed hashing operations.
- **math.h**: Provides basic mathematical functions, including `exp`, `sin`, `cos`, and `log`.
- **stdlib.h**: Used for dynamic memory allocation and other standard utilities.
- **stdint.h**: Provides fixed-width integer types like `uint8_t` and `uint64_t`.
- **endian.h**: Provides macros for detecting and converting between different endianness formats.
- **fenv.h**: Used for manipulating and querying the doubleing-point environment, such as rounding behavior.

## Example

Here is an example of how to generate a Hoohash matrix and perform matrix-vector multiplication:

```c
#include "hoohash.h"
#define DOMAIN_HASH_SIZE 32
int main() {
    uint8_t prePowHash[DOMAIN_HASH_SIZE] = {
        0x82, 0xb1, 0xd1, 0x7c, 0x5e, 0x22, 0x00, 0xa0, 0x56, 0x59, 0x56, 0xb7, 0x11, 0x48, 0x5a, 0x2c, 0xba, 0x6d, 0xa9, 0x09, 0xe5, 0x88, 0x26, 0x15, 0x82, 0xc2, 0xf4, 0x65, 0xec, 0x2e, 0x3d, 0x3f
    };
    memcpy(state.prePowHash, prePowHash, DOMAIN_HASH_SIZE);
    state.Timestamp = 1727011258677;
    state.Nonce = 7794931619413402210;
    generateHoohashMatrix(prePowHash, state.mat);
    uint8_t result[DOMAIN_HASH_SIZE];
    CalculateProofOfWorkValue(state, result);
    printf("Proof of work hash (Hex): %s\n", encodeHex(result, DOMAIN_HASH_SIZE));
    return 0;
}
```

## Credits

I’d like to acknowledge those who have contributed to the development of Hoohash:

- Doktor83 – Thank you for your valuable assistance with Hoohash v1.0.0 & v1.0.1.
- Lolliedieb – Appreciate your insight regarding the LUT in v1.0.0 & v1.0.1.
- EhssanD – Grateful for your thoughtful feedback and support on Hoohash v1.1.0.

## Conclusion

This project provides a set of cryptographic and mathematical tools for generating complex hash-based values, performing advanced matrix operations, and computing proof-of-work solutions. The Hoohash algorithm, in particular, offers a unique approach to matrix manipulation and non-linear transformations, making it suitable for applications in blockchain and cryptographic systems.
