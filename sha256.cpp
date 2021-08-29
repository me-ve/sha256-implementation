#include <iostream>
#include <cmath>
#include <fstream>
#include <vector>

typedef unsigned long long uint64;
typedef unsigned int uint;
typedef unsigned char uint8;

const uint PRIME_NO_64 = 311;
const int CHUNK_SIZE = 512;

std::string num2bin(uint64 c, int size){
	std::string bin = "";
	while (c){
		char b = '0' + c%2;
		bin = b + bin;
		c >>= 1;
	}
	while (bin.length() != size){
		bin = '0' + bin;
	}
	return bin;
}
std::string msg2bin(std::string msg){
	std::string bin = "";
	for(int i = 0; i < msg.length(); i++){
		char c = msg[i];
		bin += num2bin(c, 8);
	}
	return bin;
}
uint frac_of_root(uint x, int n){
	double root;
	switch(n){
		case 2:
			root = sqrt(x);
			break;
		case 3:
			root = cbrt(x);
			break;
		default:
			root = pow(x, 1.0/n);
			break;
	}
	root = remainder(root, 1);
	root = ldexp(root, 32);
	uint result = (uint)(floor(root));
	return result;
}
bool is_prime(uint x){
	switch(x){
		case 0:
		case 1:
		return false;
		case 2:
		case 3:
		return true;
		default:
		if(x%2==0) return false;
		for(uint i=3; i*i<=x; i+=2){
			if(x%i==0) return false;
		}
		return true;

	}
}
std::vector<uint> get_primes(uint min, uint max){
	std::vector<uint> primes = {};
	for(int i=min; i<=max; i<=4 ? i++ : i+=2){
		if(is_prime(i)) primes.push_back(i);
	}
	return primes;
}
uint bin2uint(std::string bin){
	if(bin.length()<=32){
		int value = 0;
		for(int i=0; i<32; i++){
			value += (bin[31-i]%2 << i);
		}
		return value;
	}
	else return 0xFFFFFFFF;
}
uint rotr(uint x, uint8 r){
	if(r == 0) return x;
	return (x >> r) | (x << (32 - r));
}

std::string transform_sha256_format(std::string msg){
	std::string bin = msg2bin(msg);
	int length = bin.length();
	bin += '1';
	while((bin.length()+64)%CHUNK_SIZE){
		bin += '0';
	}
	bin += num2bin(length, 64);
	return bin;
}
// main algorythm
std::string sha256_hash(std::string msg){
	//fractional parts of
	uint h[8];	//the 8 first prime numbers square roots, initial hash values
	uint k[64]; //the 64 first prime numbers cube roots
	std::vector<uint> primes = get_primes(2, PRIME_NO_64);
	for(int i=0; i<8; i++){
		h[i] = frac_of_root(primes[i], 2);
	}
	for(int i=0; i<64; i++){
		k[i] = frac_of_root(primes[i], 3);
	}
	std::string encoded_msg = transform_sha256_format(msg);
	std::string hash;
	int chunks = encoded_msg.length() >> 9; // length / 512
	for(int i=0; i<chunks; i++){
		int chunk_start = i << 9; // chunk * 512
		uint w[64];
		std::string chunk = encoded_msg.substr(chunk_start, CHUNK_SIZE);
		for(int j=0; j<16; j++){
			int part_start = j << 5; // part * 32
			std::string chunk_part = chunk.substr(part_start, 32);
			w[j] = bin2uint(chunk_part);
		}
		uint s0, s1;
		for(int j=16; j<64; j++){
			s0 = rotr(w[j-15], 7) ^ rotr(w[j-15], 18) ^ (w[j-15]>>3);
			s1 = rotr(w[j-2], 17) ^ rotr(w[j-2], 19) ^ (w[j-2]>>10);
			w[j] = w[j-16] + s0 + w[j-7] + s1;
		}
		uint v[8];
		for(int n=0; n<8; n++){
			v[n] = h[n];
		}
		// Compression loop
		for(int j=0; j<64; j++){
			s1 = rotr(v[4], 6) ^ rotr(v[4], 11) ^ rotr(v[4], 25);
			uint ch = (v[4] & v[5]) ^ (~(v[4]) & v[6]);
			uint temp1 = v[7] + s1 + ch + k[j] + w[j];
			s0 = rotr(v[0], 2) ^ rotr(v[0], 13) ^ rotr(v[0], 22);
			uint maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
			uint temp2 = s0 + maj;
			for(int n=7; n>=0; n--){
				switch(n){
					case 4:
					v[n] = v[n-1] + temp1;
					break;
					case 0:
					v[n] = temp1 + temp2;
					break;
					default:
					v[n] = v[n-1];
					break;
				}
			}
		}
		// Modify final values of hash
		hash = "";
		for(int n=0; n<8; n++){
			h[n] += v[n];
			char hex[8];
			sprintf(hex, "%x", h[n]);
			hash += hex;
		}
	}
	return hash;
}
int main(int argc, char** argv){
	if(argc != 2){
		printf("Usage: %s <input_file>\n", argv[0]);
		exit(1);
	}
	std::ifstream input(argv[1], std::ifstream::in);
	if(!input.is_open()){
		printf("File %s could not have been opened.", argv[1]);
		exit(2);
	}
	std::string msg = "";
	char c;
	while(input.get(c)){
		msg += c;
	}
	input.close();
	if(msg.back() == '\n'){
		msg.pop_back();
	}
	std::string hash = sha256_hash(msg);
	printf("Message:\n%s\n", msg.data());
	printf("Hash:\n%s\n", hash.data());
	return 0;
}