#include<stdlib.h>
#include<stdint.h>
#include<stdio.h>

#include"sha3.h"
enum program_mode {Help, Hash, Crack};

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

void print_help();

int main(int argc, char** argv)
{
	enum program_mode curr_mode = Help;
	int thread_num = 1, hashed_msg_len;
	char *arg, *text_to_hash;
	uint16_t hash_to_crack[16];
	for(int i=1; i<argc; i++) {
		arg = argv[i];
		if(arg[0] == '-') {
			switch(arg[1]) {
			case 'h':
				curr_mode = Help;
				break;
			case 'e':
				curr_mode = Hash;
				text_to_hash = argv[++i];
				break;
			case 'd':
				curr_mode = Crack;
				hashed_msg_len = atoi(argv[++i]);
				for(int h_i=0; h_i<8; h_i++) {
					hash_to_crack[h_i] = strtoul(argv[++i], 0, 16) << 8;
					hash_to_crack[h_i] |= strtoul(argv[++i], 0, 16);
				}
				break;
			case 't':
				thread_num = atoi(argv[++i]);
				break;
			}
		}
	}

	switch (curr_mode) {
	case Hash:
		hash_msg((uint8_t*)text_to_hash);
		break;
	case Crack:
		crack_hash(hashed_msg_len, hash_to_crack, thread_num);
		break;
	case Help:
	default:
		print_help();
		break;
	}
	return 0;
}

void print_help() {
	printf("PK project tool.\n");
	printf("Flags:\n");
	printf("\t-h: displays this message.\n");
	printf("\t-e {TEXT}: Hashes given {TEXT}.\n");
	printf("\t-d {LEN} 16x{HEX_BYTE}: Attempts to crack the hash.\n");
	printf("\t\t {LEN} - Length of hashed message\n");
	printf("\t\t 16x{HEX_BYTE} - spacebar separated 16 8-bit hex numbers.\n");
	printf("\t-t: numbers of threads used for hash cracking, only used in -d\n");

}
