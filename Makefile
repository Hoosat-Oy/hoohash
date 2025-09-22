# Compiler and flags - NVCC with MSVC-like optimizations (FP64 precision preserved)
CC = nvcc

# Precision-safe optimizations (no fast-math)
OPT_CFLAGS = -O3 -march=native -mtune=native -funroll-loops \
             -finline-functions -fomit-frame-pointer \
             -fstrict-aliasing -fprefetch-loop-arrays -ftree-vectorize \
             -fno-semantic-interposition -fno-stack-check -fno-stack-protector -fno-fast-math

DEBUG_CFLAGS = -g -O0 -Wall -Wextra
RELEASE_CFLAGS = $(OPT_CFLAGS) -DNDEBUG -fPIC
HOST_CFLAGS = $(RELEASE_CFLAGS) -std=c99 -D_GNU_SOURCE -lm

# NVCC flags - precision-safe, no fast-math
NVCC_FLAGS = -Xcompiler "$(HOST_CFLAGS)" \
             --maxrregcount=64 \
             -Wno-deprecated-gpu-targets \
             --prec-div=false --prec-sqrt=false  # Only these precision flags for speed

# NVCC linker flags
LDFLAGS = -Xcompiler "-lm -fuse-ld=mold"

# Build mode
MODE ?= release
ifeq ($(MODE),debug)
    NVCC_FLAGS := -Xcompiler "$(DEBUG_CFLAGS) -fPIC -std=c99 -D_GNU_SOURCE" -g -G
    LDFLAGS := -Xcompiler "-lm"
endif

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
	@echo "AR    $(TARGET)"
	ar rcs $@ $(OBJS)

# Compile C files with NVCC (precision-safe optimized)
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@echo "NVCC  $<"
	$(CC) $(NVCC_FLAGS) -c $< -o $@

# Test target
test: NVCC_FLAGS += -Xcompiler "-DTEST"
test: $(TEST_BIN)

$(TEST_BIN): $(OBJS) $(TEST_OBJ) | $(BUILD_DIR)
	@echo "LINK  $(TEST_BIN)"
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(TEST_OBJ) \
		-Xcompiler "-I../blake3/c" \
		../blake3/c/build/libblake3.a

$(TEST_OBJ): $(TEST_SRC) | $(BUILD_DIR)
	@echo "NVCC  $(TEST_SRC)"
	$(CC) $(NVCC_FLAGS) -c $< -o $@

# Clean
clean:
	rm -rf $(BUILD_DIR) gmon.out *.gcda *.gcno *.profraw

.PHONY: all test clean 