#include<stdlib.h>
#include<stdint.h>
#include<stdio.h>
#include<string.h>
#include<math.h>
#include<pthread.h>

#define BLOCK_SIZE 20
#define ALLOWED_CHARACTERS_SIZE 79

#define ROL(x, shift)((x << (shift)) | (x >> (16 - (shift))))
#define NEG(x)((~x)&0xFFFF)

char allowed_characters[ALLOWED_CHARACTERS_SIZE] = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#%^-_=+([{<)]}>";

uint16_t r[10] = {0x2E60, 0xD05E, 0x9266, 0xB6A6, 0x8059, 0x6FDE, 0xF62D, 0x8A86, 0x8C47, 0xD6A4};

pthread_t* thread;
pthread_attr_t attr;
uint thread_msg_len = 0;
uint16_t thread_hash_msg[8];
uint8_t** thread_msg_chars;
uint g_thread_num = 1;
uint thread_found = 0;

static int modulo(int a, int b)
{
	const int result = a % b;
	return result >= 0 ? result : result + b;
}

void sha3_keccak(uint16_t state[5][5]);

uint16_t* hash(uint8_t* msg, int msg_len);

void crack_hash_single(int msg_len, uint16_t hash_msg[8]);

void crack_threads(int msg_len, uint16_t hash_msg[8]);

void* thread_main(void *args);

void sha3_keccak(uint16_t a[5][5])
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
}

uint16_t* hash(uint8_t* msg, int msg_len)
{
	// Fill the full block
	uint32_t msg_filled_len = msg_len + (BLOCK_SIZE - msg_len%BLOCK_SIZE);
	uint8_t* msg_filled = (uint8_t*) calloc(msg_filled_len, sizeof(uint8_t));
	memcpy(msg_filled, msg, msg_len);
	msg_filled[msg_len] = 0x80;

	uint16_t a[5][5];
	for(int i=0; i<5; i++)
		for(int j=0; j<5; j++)
			a[i][j] = 0;

	// For every block
	for(uint block=0; block<msg_filled_len/BLOCK_SIZE; block++) {
		// Update state
		for(int i=0; i<2; i++)
			for(int j=0; j<5; j++)
				a[i][j] ^= (msg_filled[block*BLOCK_SIZE + 2*(i*5+j)] << 8) | msg_filled[block*BLOCK_SIZE + 2*(i*5+j) + 1];
		// Main algorithm
		sha3_keccak(a);
	}

	uint16_t* res = malloc(8 * sizeof(uint16_t));
	for(int i=0; i<5; i++)
		res[i] = a[0][i];
	sha3_keccak(a);
	for(int i=0; i<3; i++)
		res[i+5] = a[0][i];

	free(msg_filled);
	return res;
}

// Simpler variant
void crack_hash_single(int msg_len, uint16_t hash_msg[8])
{
	uint16_t a[5][5];
		for(int i=0; i<5; i++)
			for(int j=0; j<5; j++)
				a[i][j] = 0;
	uint8_t* msg_chars = calloc(msg_len, sizeof(uint8_t));
	uint8_t* msg = calloc(msg_len + (BLOCK_SIZE - msg_len%BLOCK_SIZE), sizeof(uint8_t));

	msg[msg_len] = 0x80;

	for(int i=0; i<pow(ALLOWED_CHARACTERS_SIZE, msg_len); i++) {
		for(int char_index=0; char_index<msg_len; char_index++) {
			if(msg_chars[char_index] == ALLOWED_CHARACTERS_SIZE) {
				msg_chars[char_index] = 0;
				msg_chars[char_index+1] += 1;
			}
			msg[char_index] = allowed_characters[msg_chars[char_index]];
		}
		for(int i=0; i<5; i++)
					for(int j=0; j<5; j++)
						a[i][j] = 0;
		for(int i=0; i<2; i++)
			for(int j=0; j<5; j++)
				a[i][j] ^= (msg[2*(i*5+j)] << 8) | msg[2*(i*5+j) + 1];

		uint16_t our_hash[8];
		sha3_keccak(a);
		for(int i=0; i<5; i++)
			our_hash[i] = a[0][i];
		if(memcmp(our_hash, hash_msg, 5) == 0) {
			printf("Potential candidate\n");
			sha3_keccak(a);
			for(int i=0; i<3; i++)
				our_hash[i+5] = a[0][i];
			if(memcmp(our_hash+5, hash_msg+5, 3) == 0) {
				printf("Cracked hash, the answer is: ");
				for(int result_i=0; result_i < msg_len; result_i++)
					printf("%c", allowed_characters[msg_chars[result_i]]);
				printf("\n");
				free(msg);
				free(msg_chars);
				return;
			}
		}
		msg_chars[0] += 1;
	}

	printf("No result");
	free(msg);
	free(msg_chars);
}

void crack_threads(int msg_len, uint16_t hash_msg[8])
{
	thread_msg_len = msg_len;
	memcpy(thread_hash_msg, hash_msg, 8 * sizeof(uint16_t));

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);


	for(uint i=0; i<g_thread_num; i++) {
		thread_msg_chars[i] = calloc(thread_msg_len, sizeof(uint8_t));
		thread_msg_chars[i][thread_msg_len-1] = i * (ALLOWED_CHARACTERS_SIZE/g_thread_num);
		pthread_create(&thread[i], &attr, thread_main, (void*) thread_msg_chars[i]);
	}

	void* threadstatus;
	for(uint i=0; i<g_thread_num; i++)
		pthread_join(thread[i], &threadstatus);
	for(uint i=0; i<g_thread_num; i++)
		free(thread_msg_chars[i]);
}

void* thread_main(void *args)
{
	uint8_t* msg_chars = (uint8_t*) args;

	uint16_t a[5][5];
		for(int i=0; i<5; i++)
			for(int j=0; j<5; j++)
				a[i][j] = 0;
	uint8_t* msg = calloc(thread_msg_len + (BLOCK_SIZE - thread_msg_len%BLOCK_SIZE), sizeof(uint8_t));

	msg[thread_msg_len] = 0x80;
	uint64_t limit = pow(ALLOWED_CHARACTERS_SIZE, thread_msg_len)/g_thread_num;

	for(uint64_t i=0; i<limit; i++) {
		if(thread_found)
			break;
		if(i%1000000 == 0)
			printf("%f%%\n", i*100.0/limit);
		for(uint char_index=0; char_index<thread_msg_len; char_index++) {
			if(msg_chars[char_index] == ALLOWED_CHARACTERS_SIZE) {
				msg_chars[char_index] = 0;
				msg_chars[char_index+1] += 1;
			}
			msg[char_index] = allowed_characters[msg_chars[char_index]];
		}
		for(int i=0; i<5; i++)
					for(int j=0; j<5; j++)
						a[i][j] = 0;
		for(int i=0; i<2; i++)
			for(int j=0; j<5; j++)
				a[i][j] ^= (msg[2*(i*5+j)] << 8) | msg[2*(i*5+j) + 1];

		uint16_t our_hash[8];
		sha3_keccak(a);
		for(int i=0; i<5; i++)
			our_hash[i] = a[0][i];
		if(memcmp(our_hash, thread_hash_msg, 5) == 0) {
			printf("Potential candidate\n");
			sha3_keccak(a);
			for(int i=0; i<3; i++)
				our_hash[i+5] = a[0][i];
			if(memcmp(our_hash+5, thread_hash_msg+5, 3) == 0) {
				printf("Cracked hash, the answer is: ");
				for(uint result_i=0; result_i<thread_msg_len; result_i++)
					printf("%c", allowed_characters[msg_chars[result_i]]);
				printf("\n");
				free(msg);
				free(msg_chars);
				thread_found = 1;
				return NULL;
			}
		}
		msg_chars[0] += 1;
	}

	printf("No result\n");
	free(msg);
	return NULL;
}

void crack_hash(int msg_len, uint16_t hash_msg[8], int thread_num) {
	if(thread_num == 1) {
		crack_hash_single(msg_len, hash_msg);
	} else {
		g_thread_num = thread_num;
		thread = malloc(thread_num*sizeof(pthread_t));
		thread_msg_chars = malloc(thread_num*sizeof(uint8_t*));
		crack_threads(msg_len, hash_msg);
		free(thread);
		free(thread_msg_chars);
	}
}

void hash_msg(uint8_t* msg) {
	uint16_t* res = hash(msg, strlen((char*)msg));

	for(int i=0; i<8; i++)
		printf("%04X", res[i]);
	printf("\n");
	free(res);
}
