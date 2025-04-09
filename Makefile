# Compiler and flags
CC = gcc
CFLAGS = -fPIC -g -Wall -Wextra
LDFLAGS = -shared

# Paths
BUILD_DIR = build
SRCS = hoohash.c bigint.c
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)
TARGET = $(BUILD_DIR)/lib-hoohash.so
TEST_SRC = main_test.c
TEST_OBJ = $(BUILD_DIR)/main_test.o
TEST_BIN = $(BUILD_DIR)/hoohash_test

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJS) | $(BUILD_DIR)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lm -lblake3

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

test: CFLAGS += -DTEST
test: $(TEST_BIN)

$(TEST_BIN): $(OBJS) $(TEST_OBJ)
	$(CC) -o $@ $(OBJS) $(TEST_OBJ) -lm -lblake3

$(TEST_OBJ): $(TEST_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)