#include<stdlib.h>
#include<stdint.h>
#include<stdio.h>
#include<string.h>
#include<math.h>
#include<pthread.h>

#define THREAD_NUM 4

#define BLOCK_SIZE 20
#define ALLOWED_CHARACTERS_SIZE 79

#define ROL(x, shift)((x << (shift)) | (x >> (16 - (shift))))
#define NEG(x)((~x)&0xFFFF)

char allowed_characters[ALLOWED_CHARACTERS_SIZE] = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#%^-_=+([{<)]}>";

uint16_t r[10] = {0x2E60, 0xD05E, 0x9266, 0xB6A6, 0x8059, 0x6FDE, 0xF62D, 0x8A86, 0x8C47, 0xD6A4};

pthread_t thread[THREAD_NUM];
pthread_attr_t attr;
int thread_msg_len = 0;
uint16_t  thread_hash_msg[8];
uint8_t* thread_msg_chars[THREAD_NUM];
int thread_found = 0;

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

void sha3_keccak(uint16_t state[5][5]);

uint16_t* hash(uint8_t* msg, int msg_len);

void test_hashing();

void crack_hash(int msg_len, uint16_t hash_msg[8]);

void crack_threads(int msg_len, uint16_t hash_msg[8]);

void* thread_main(void *args);

int main(int argc, char** argv)
{
	uint16_t hash_msg[5][8] = {
			{0x69F7, 0x0616, 0xCF70, 0xA87B, 0x204B, 0xF042, 0x34A4, 0xE8FB},
			{0x78AA, 0xE402, 0x87BC, 0xBCF8, 0x29F2, 0x1B57, 0xA548, 0x49FF},
			{0xA84C, 0xB68B, 0xB4E1, 0xB536, 0xE507, 0x98D0, 0xBEE9, 0x5BBD},
			{0x99E3, 0xA4B6, 0x3674, 0x04E0, 0x284B, 0x9FE7, 0xE246, 0x6fAA},
			{0xCB2F, 0x8DF7, 0xA84A, 0x6E1E, 0x9C4D, 0x69D8, 0x0B5D, 0x29D4}
	};
	//crack_hash(2, hash_msg[0]);
	//crack_hash(3, hash_msg[1]);
	//crack_hash(4, hash_msg[2]);

	//crack_threads(2,  hash_msg[0]);
	//crack_threads(3,  hash_msg[1]);
	//crack_threads(4,  hash_msg[2]);
	//crack_threads(5,  hash_msg[3]);
	crack_threads(6,  hash_msg[4]);
	return 0;
}

void test_hashing()
{
	uint8_t* inputs[6] = {
			(uint8_t*)"",
			(uint8_t*)"AbCxYz",
			(uint8_t*)"1234567890",
			(uint8_t*)"Ala ma kota, kot ma ale.",
			(uint8_t*)"Ty, ktory wchodzisz, zegnaj sie z nadzieja.",
			(uint8_t*)"Litwo, Ojczyzno moja! ty jestes jak zdrowie;",
	};

	for(int input=0; input<6; input++) {
		uint16_t* res = hash(inputs[input], strlen((const char*)inputs[input]));
		printf("%s : ", inputs[input]);
		for(int i=0; i<8; i++)
			printf("%04X ", res[i]);
		printf("\n");
		free(res);
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
	for(int block=0; block<msg_filled_len/BLOCK_SIZE; block++) {
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

// Simple variant for 1 block message only
void crack_hash(int msg_len, uint16_t hash_msg[8])
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


	for(int i=0; i<THREAD_NUM; i++) {
		thread_msg_chars[i] = calloc(thread_msg_len, sizeof(uint8_t));
		thread_msg_chars[i][thread_msg_len-1] = i * (ALLOWED_CHARACTERS_SIZE/THREAD_NUM);
		pthread_create(&thread[i], &attr, thread_main, (void*) thread_msg_chars[i]);
	}

	void* threadstatus;
	for(int i=0; i<THREAD_NUM; i++)
		pthread_join(thread[i], &threadstatus);
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
	int limit = pow(ALLOWED_CHARACTERS_SIZE, thread_msg_len)/THREAD_NUM;

	for(int i=0; i<limit; i++) {
		if(thread_found)
			break;
		if(i%100 == 0)
			printf("%f%%\n", i*100.0/limit);
		for(int char_index=0; char_index<thread_msg_len; char_index++) {
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
				for(int result_i=0; result_i < thread_msg_len; result_i++)
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
