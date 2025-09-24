# Compiler and settings
CC = nvcc
OPT_FLAGS = -O2
DEBUG_FLAGS = -g -O0 -Wall -Wextra
RELEASE_FLAGS = $(OPT_FLAGS) -DNDEBUG -fPIC -lm

# NVCC flags for CUDA compilation
NVCC_FLAGS = -Xcompiler " -fPIC -g -O2 -lm"
LDFLAGS = -Xcompiler "-lm"



# Directories and files
BUILD_DIR = build
SRCS = hoohash.c bigint.c
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)
TARGET = $(BUILD_DIR)/lib-hoohash.a
TEST_SRC = main_test.c
TEST_OBJ = $(BUILD_DIR)/main_test.o
TEST_BIN = $(BUILD_DIR)/hoohash_test

# Default target
all: $(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build static library
$(TARGET): $(OBJS) | $(BUILD_DIR)
	ar rcs $@ $(OBJS)

# Compile source files
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(NVCC_FLAGS) -c $< -o $@

# Test target
test: NVCC_FLAGS += -Xcompiler "-DTEST"
test: $(TEST_BIN)

# Link test binary
$(TEST_BIN): $(OBJS) $(TEST_OBJ) | $(BUILD_DIR)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(TEST_OBJ) -Xcompiler "-I../blake3/c" ../blake3/c/build/libblake3.a

# Compile test source
$(TEST_OBJ): $(TEST_SRC) | $(BUILD_DIR)
	$(CC) $(NVCC_FLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) gmon.out *.gcda *.gcno *.profraw

.PHONY: all test clean