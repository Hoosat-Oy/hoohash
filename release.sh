#!/bin/bash

# Ensure the script stops if any command fails
set -e

# Ask for the version number
read -p "Enter the version number: " VERSION

# Step 1: Build the project using make
echo "Building the project..."
make clean
make all

# Define the shared library path
LIB_PATH="build/lib-hoohash.so"

# Check if the library was created
if [[ ! -f "$LIB_PATH" ]]; then
    echo "Error: $LIB_PATH not found. Build might have failed."
    exit 1
fi

# Step 2: Generate SHA-1 hash of the shared library
SHA1_HASH=$(sha1sum "$LIB_PATH" | awk '{print $1}')
echo "SHA-1 hash of the library: $SHA1_HASH"

# Step 3: Rename the .so file to include the version
NEW_LIB_NAME="build/lib-hoohash-${VERSION}.so"
mv "$LIB_PATH" "$NEW_LIB_NAME"
echo "Renamed library to $NEW_LIB_NAME"

# Step 4: Write the SHA-1 hash to a .sha1 file
SHA1_FILE="build/lib-hoohash-${VERSION}.sha1"
echo "$SHA1_HASH  $NEW_LIB_NAME" > "$SHA1_FILE"
echo "SHA-1 hash written to $SHA1_FILE"

echo "Build, versioning, and SHA-1 checksum generation complete."