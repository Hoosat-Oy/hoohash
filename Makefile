# Compiler and flags
# Use gcc for C files, nvcc only when needed for CUDA
CC = gcc
NVCC = nvcc
CFLAGS = -fPIC -g -Wall -Wextra -lm -std=c99 -D_GNU_SOURCE
NVCC_FLAGS = -Xcompiler "$(CFLAGS)" -Wno-deprecated-gpu-targets
LDFLAGS = 

# Paths
BUILD_DIR = build
SRCS = hoohash.c bigint.c
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)
TARGET = $(BUILD_DIR)/lib-hoohash.a
TEST_SRC = main_test.c
TEST_OBJ = $(BUILD_DIR)/main_test.o
TEST_BIN = $(BUILD_DIR)/hoohash_test

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build static library
$(TARGET): $(OBJS) | $(BUILD_DIR)
	ar rcs $@ $(OBJS)

# Compile C files with gcc
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Special rule for hoohash.c if you need CUDA version
$(BUILD_DIR)/hoohash_cuda.o: hoohash.c | $(BUILD_DIR)
	$(NVCC) $(NVCC_FLAGS) -c $< -o $@

# Test target
test: CFLAGS += -DTEST
test: $(TEST_BIN)

$(TEST_BIN): $(OBJS) $(TEST_OBJ) | $(BUILD_DIR)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(TEST_OBJ) -lm -I../blake3/c ../blake3/c/build/libblake3.a

$(TEST_OBJ): $(TEST_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# CUDA-enabled library (if needed)
cuda_lib: OBJS = $(BUILD_DIR)/hoohash_cuda.o $(BUILD_DIR)/bigint.o
cuda_lib: $(TARGET)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all test clean cuda_lib