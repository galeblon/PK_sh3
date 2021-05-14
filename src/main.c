/*
 * main.c
 *
 *  Created on: May 14, 2021
 *      Author: gales
 */

#include<stdlib.h>
#include<stdint.h>
#include<stdio.h>

#define ROL(x, shift)((x << (shift)) | (x >> (16 - (shift))))
#define NEG(x)((~x)&0xFFFF)

uint16_t a[5][5] = {{0x0001, 0x0203, 0x0405, 0x0607, 0x0809}, {0x0A0B, 0x0C0D, 0x0E0F, 0x1011, 0x1213}};
uint16_t r[10] = {0x2E60, 0xD05E, 0x9266, 0xB6A6, 0x8059, 0x6FDE, 0xF62D, 0x8A86, 0x8C47, 0xD6A4};

int modulo(int a, int b)
{
	const int result = a % b;
	return result >= 0 ? result : result + b;
}

void print_matrix(uint16_t matrix[5][5])
{
	for(int i=0; i<5; i++) {
		for(int j=0; j<5; j++) {
			printf("%04X ", matrix[i][j]);
		}
		printf("\n");
	}
	printf("\n");
}

void sha3_keccak(uint16_t state[5][5], uint8_t block[20]);

int main(int argc, char** argv)
{
	// Read input
	// TODO
	uint8_t input_block[20] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
							  0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
							  0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13};

	// Fill to multiple of 20
	// TODO

	// Main algorithm
	// For now testing on known values just the rounds.
	sha3_keccak(a, input_block);
	sha3_keccak(a, input_block);

	// Print result
	// TODO
	return 0;
}

void sha3_keccak(uint16_t state[5][5], uint8_t block[20])
{
	uint16_t c[5];
	uint16_t d[5];
	int16_t b[5][5];
	int i,j;
	for(int round=0; round<10; round++) {
		// Step 1. Theta
		for(i=0; i<5; i++)
			c[i] = a[i][0]^a[i][1]^a[i][2]^a[i][3]^a[i][4];
		for(i=0; i<5; i++)
					d[i] = c[modulo(i-1, 5)]^ROL(c[modulo(i+1, 5)], 1);
		for(i=0; i<5; i++)
			for(j=0; j<5; j++)
				a[i][j] ^= d[i];

		// Step 2. Rho
		for(i=0; i<5; i++)
			for(j=0; j<5; j++)
				a[i][j] = ROL(a[i][j], modulo(9*i + j, 16));

		// Step 3. Pi
		for(i=0; i<5; i++)
			for(j=0; j<5; j++)
				b[modulo(i+3*j, 5)][i] = a[i][j];
		// Step 4. Chi
		for(i=0; i<5; i++)
			for(j=0; j<5; j++)
				a[i][j] = b[i][j]^((NEG(b[modulo(i+1, 5)][j]))&(b[modulo(i+2, 5)][j]));
		// Step 5. Iota
		a[0][0] ^= r[round];
	}
	print_matrix(a);
	return;
}
