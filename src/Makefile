CC = gcc
CFLAGS = -Wall -Wextra -pedantic -O3
SRCS = main.c sha3.c

LBR = -lm -lpthread
BIN = pk_sha3

all: pk

pk: 
	$(CC) $(SRCS) $(CFLAGS) -o $(BIN) $(LBR)

