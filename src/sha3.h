#ifndef SRC_SHA3_H_
#define SRC_SHA3_H_

void hash_msg(uint8_t* msg);

void crack_hash(int msg_len, uint16_t hash_msg[8], int thread_num);


#endif /* SRC_SHA3_H_ */
