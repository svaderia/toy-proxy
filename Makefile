# Compiler and flags
CC = gcc
CFLAGS = -Wall -g

LDFLAGS = -levent

# Target executable
TARGET = proxy

# Source files
SRCS = proxy.c queue.c

# Object files (generated from the source files)
OBJS = $(SRCS:.c=.o)

# Default rule to build the target executable
all: $(TARGET)

# Rule to link object files into the final executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Rule to compile .c files into .o files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule to remove object files and the executable
clean:
	rm -f $(OBJS) $(TARGET)

