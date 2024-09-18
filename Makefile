# Define the compiler and flags
CC = gcc
CFLAGS = -fPIC
LDFLAGS = -shared

# Source files
SRCS = hoohash.c bigint.c

# Object files (replace .c with .o in source files)
OBJS = $(SRCS:.c=.o)

# Output library name
TARGET_LIB = lib-hoohash.so

# Default rule: build the dynamic library
all: $(TARGET_LIB)

# Rule to create the shared library
$(TARGET_LIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

# Rule to compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule to remove generated files
clean:
	rm -f $(OBJS) $(TARGET_LIB)
