#include <stdio.h>
#include <string.h>
#include "rijndael.h"

#define INP_STR "This string should be encrypted"
#define ENCR_MSG(inp, outp, key, obj)	\
	obj.init(key,cppcrypto::block_cipher::direction::encryption); \
	obj.encrypt_block(inp, (const unsigned char*) outp); 
#define DECR_MSG(inp, outp, key, obj)	\
	obj.init(key,cppcrypto::block_cipher::direction::decryption); \
	obj.decrypt_block(inp, (const unsigned char*) outp);

void process_msg(char* inp, char* out, char* key );

uint8_t* key;
char* inp_buf = NULL;
char* out_buf = NULL;

using namespace cppcrypto;

/*
 * usage <appname> [-f] <filepath> -d [<path/to/outp/file>] -k [<key>] -d [decrypt] -e [encrypt] -t [<des>|<aes128/192/256>|<kal128/256/512>]
 */
int main(int argc, char** argv){
	//parse args
	
	//check that input file exists
	//check if input file is not empty 
	//prepare all krypto checks
		//for des - only 56 bit keys
		//for aes - 128/192/256 bit keys
		//for kalina - 128/256/512
	int str_size = strlen(INP_STR);
	key = (uint8_t*)"abcdefghijklmnop";
	inp_buf = new char[str_size];
	memcpy(inp_buf, INP_STR, str_size);
	out_buf = new char[str_size];
	memcpy(out_buf, INP_STR, str_size);
	
	rijndael128_128 rijndael128_128_obj;
	ENCR_MSG(inp_buf, out_buf, key, rijndael128_128_obj);
	
	
	printf("out_buf = %s\n", out_buf);
	
	memset(inp_buf, 40, str_size);
	DECR_MSG(out_buf, inp_buf, key, rijndael128_128_obj);
	
	
	printf("decripted inp_buf = %s\n", inp_buf);
	
	
	if(out_buf)
		delete out_buf;
	out_buf = NULL;

	if(inp_buf)
		delete inp_buf;
	inp_buf = NULL;

	//init parameters
		
	//if key is not specified - generate key automatically
		
	//encrypt/decrypt depending on specified alhorythm

	//save to file or output to console
	//save generated key to file or print to console
	
	return 0;
}
