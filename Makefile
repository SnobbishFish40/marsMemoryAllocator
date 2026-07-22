CC = gcc
# Wall and Wextra for warnings, -g for gdb usage, -fPIC for .so, -pthread for thread safe code
CFLAGS = -Wall -Wextra -g -fPIC -pthread

LIBRARY = liballocator.so
EXECUTABLE = runme

LIB_SRCS = allocator.c
EXE_SRC = runme.c

LIB_OBJS = $(LIB_SRCS:.c=.o)
EXE_OBJ = $(EXE_SRC:.c=.o)

HEADERS = allocator.h

all: $(LIBRARY) $(EXECUTABLE)

$(LIBRARY): $(LIB_OBJS)
	$(CC) -shared -o $(LIBRARY) $(LIB_OBJS)

$(EXECUTABLE): $(LIB_OBJS) $(EXE_OBJ)
	$(CC) -o $(EXECUTABLE) $(LIB_OBJS) $(EXE_OBJ)

allocator.o: allocator.c $(HEADERS)
	$(CC) $(CFLAGS) -c allocator.c -o allocator.o

runme.o: runme.c $(HEADERS)
	$(CC) $(CFLAGS) -c runme.c -o runme.o

test: $(EXECUTABLE)
	./$(EXECUTABLE) $(ARGS)

clean:
	rm -f $(LIB_OBJS) $(EXE_OBJ) $(LIBRARY) $(EXECUTABLE)

help:
	@echo "make all: Build library and executable"
	@echo "make test: Build and execute runme tests"
	@echo "make clean: Delete build artifacts"

.PHONY: all test clean help
