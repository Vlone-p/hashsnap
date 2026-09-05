CC = gcc
CFLAGS = -O2 -Wall -Wextra -Iinclude -pthread
SRC = src/main.c src/cracker.c src/rules.c src/md5.c src/sha1.c src/sha256.c src/sha512.c src/md4.c src/ntlm.c src/colors.c
OBJ = $(SRC:.c=.o)
TARGET = hashsnap

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

test: all
	./$(TARGET) --help
