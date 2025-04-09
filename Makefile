# Define the compiler and flags
CC = gcc
CFLAGS = -fPIC -g -Wall -Wextra -DTEST
LDFLAGS = -shared

# Source files
SRCS = hoohash.c bigint.c

# Build and output directories
BUILD_DIR = build

# Object files (replace .c with .o in source files in build folder)
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)

# Output library name
TARGET_LIB = $(BUILD_DIR)/lib-hoohash.so

# Default rule: build the dynamic library
all: $(TARGET_LIB)

# Create build directory if it does not exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Rule to create the shared library
$(TARGET_LIB): $(OBJS) | $(BUILD_DIR)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lm -lblake3

# Rule to compile source files into object files in the build directory
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Test rule to compile and link main_test.c with the object files
test: CFLAGS += -DTEST
test: $(BUILD_DIR)/main_test.o $(OBJS) | $(BUILD_DIR)
	$(CC) -o $(BUILD_DIR)/main_test $(OBJS) $(BUILD_DIR)/main_test.o -lm -lblake3

# Compile main_test.c to object file in the build directory
$(BUILD_DIR)/main_test.o: main_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c main_test.c -o $@

# Rule to build the miner target
miner: CFLAGS += -DTEST -g
miner: $(BUILD_DIR)/miner.o $(OBJS) | $(BUILD_DIR)
	$(CC) -o $(BUILD_DIR)/miner $(OBJS) $(BUILD_DIR)/miner.o -lm -lblake3 -lgmp -ljson-c

# Compile miner.c to object file in the build directory
$(BUILD_DIR)/miner.o: miner.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c miner.c -o $@
	
# Clean rule to remove generated files in the build directory
clean:
	rm -rf $(BUILD_DIR)
