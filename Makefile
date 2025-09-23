# Compiler and flags
CC = nvcc
CFLAGS = -Xcompiler -fPIC -g
# Remove -shared from LDFLAGS, it's for shared libs
LDFLAGS = -lm 

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

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

test: CFLAGS += -DTEST
test: $(TEST_BIN)

$(TEST_BIN): $(OBJS) $(TEST_OBJ) | $(BUILD_DIR)
	$(CC) -o $@ $(OBJS) $(TEST_OBJ) -lm -I../blake3/c ../blake3/c/build/libblake3.a

$(TEST_OBJ): $(TEST_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
