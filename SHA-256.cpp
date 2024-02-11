#include "SHA-256.h"

void SHA_256::make_block(std::string msg) {
	int i = 0;
	while (i < msg.size()) {
		block[i] = (char)msg[i];
		i++;
	}

	if (i < 55) {
		unsigned char a = 1;
		a = a << 7;
		block[i++] = a;

		while (i < 56) {
			block[i] = 0;
			i++;
		}

		unsigned long long b = msg.size()*8;
		unsigned long long tmp = 255;
		for (int c = 63; c > 55; c--) {
			block[c] = (b & (tmp << ((63-c)*8))) >> ((63-c)*8);
		}
	}
}



void SHA_256::make_words() {
	for (int i = 0; i < 16; i++) {
		unsigned int tmp = 0;
		for (int j = 4 * i; j < (4 * (i + 1)); j++) {
			tmp = tmp | (unsigned int)block[j];
			if (j != (4 * (i + 1) - 1)) tmp = tmp << 8;
		}
		words[i] = tmp;
	}

	for (int i = 16; i < 64; i++) {

		unsigned int tmp0 = (words[i-15] & (unsigned int)127) << 25;
		unsigned int tmp1 = (words[i - 15] >> 7) | tmp0;

		tmp0 = (words[i - 15] & (unsigned int)262143) << 14;
		unsigned int tmp2 = (words[i - 15] >> 18) | tmp0;

		tmp0 = (words[i - 2] & (unsigned int)131071) << 15;
		unsigned int tmp3 = (words[i - 2] >> 17) | tmp0;

		tmp0 = (words[i - 2] & (unsigned int)524287) << 13;
		unsigned int tmp4 = (words[i - 2] >> 19) | tmp0;

		unsigned int s0 = tmp1^tmp2^(words[i-15]>>3);
		unsigned int s1 = tmp3^tmp4^(words[i-2]>>10);
		words[i] = words[i - 16] + s0 + words[i - 7] + s1;
	}
}



SHA_256::SHA_256() {
	hash[0] = 0x6A09E667;
	hash[1] = 0xBB67AE85;
	hash[2] = 0x3C6EF372;
	hash[3] = 0xA54FF53A;
	hash[4] = 0x510E527F;
	hash[5] = 0x9B05688C;
	hash[6] = 0x1F83D9AB;
	hash[7] = 0x5BE0CD19;
}



void SHA_256::count_hash(std::string msg) {
	//for (short i = 0; i < 8; i++) printf("%x ", hash[i]);
	std::cout << '\n';
	make_block(msg);
	make_words();
	unsigned int hash_tmp[8];
	for (short i = 0; i < 8; i++) {
		hash_tmp[i] = hash[i];
	}

	for (int i = 0; i < 64; i++) {
		unsigned int tmp0 = (hash_tmp[0] & (unsigned int)3) << 30;
		unsigned int tmp1 = (hash_tmp[0] >> 2) | tmp0;

		tmp0 = (hash_tmp[0] & (unsigned int)8191) << 19;
		unsigned int tmp2 = (hash_tmp[0] >> 13) | tmp0;

		tmp0 = (hash_tmp[0] & (unsigned int)4194303) << 10;
		unsigned int tmp3 = (hash_tmp[0] >> 22) | tmp0;

		tmp0 = (hash_tmp[4] & (unsigned int)63) << 26;
		unsigned int tmp4 = (hash_tmp[4] >> 6) | tmp0;

		tmp0 = (hash_tmp[4] & (unsigned int)2047) << 21;
		unsigned int tmp5 = (hash_tmp[4] >> 11) | tmp0;

		tmp0 = (hash_tmp[4] & (unsigned int)33554431) << 7;
		unsigned int tmp6 = (hash_tmp[4] >> 25) | tmp0;

		unsigned int sigma0 = tmp1 ^ tmp2 ^ tmp3;
		unsigned int Ma = (hash_tmp[0] & hash_tmp[1]) ^ (hash_tmp[0] & hash_tmp[2]) ^ (hash_tmp[1] & hash_tmp[2]);
		unsigned int sigma1 = tmp4 ^ tmp5 ^ tmp6;
		unsigned int Ch = (hash_tmp[4] & hash_tmp[5]) ^ (~hash_tmp[4] & hash_tmp[6]);

		unsigned int t1 = hash_tmp[7] + sigma1 + Ch + constants[i] + words[i];
		unsigned int t2 = sigma0 + Ma;

		for (short j = 7; j >= 0; j--) {
			if (j == 4) hash_tmp[j] = hash_tmp[j-1] + t1;
			else if (j == 0) hash_tmp[j] = t1 + t2;
			else hash_tmp[j] = hash_tmp[j - 1];
		}
	}

	for (short i = 0; i < 8; i++) {
		hash[i] = hash[i] + hash_tmp[i];
		printf("%x ", hash[i]);
	}
}

unsigned int* SHA_256::getHash() {
	unsigned int* hash = new unsigned int[8];
	for (short i = 0; i < 8; i++) { hash[i] = this->hash[i]; }
	return hash;
}

unsigned char* SHA_256::getBits(int bits) {
	if (bits < 1) return NULL;
	short size = bits / 8;
	short excess = bits % 8;
	if (excess > 0) size++;
	unsigned char* bit_arr = new unsigned char [size];
	for (short i = 0; i < size; i++) {
		short cell = i / 4;
		short tmp_excess = i % 4;
		unsigned int tmp = hash[cell];
		bit_arr[i] = tmp | ((unsigned int)255 << (8*(3-tmp_excess)));
	}

	if (excess > 0) {
		unsigned char tmp = bit_arr[size - 1];
		unsigned char cut = 0;
		for (short i = 0; i < 8; i++) {
			cut = cut << 1;
			if (i <= excess) cut++;
		}
		bit_arr[size - 1] = tmp&cut;
	}

	return bit_arr;
}