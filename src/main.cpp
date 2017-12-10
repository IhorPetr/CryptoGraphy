#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include "rijndael.h"
#include "anubis.h"
#include "kalyna.h"
#include "md5.h"
#include "sha256.h"
#include "kupyna.h"

#define INP_STR "This string should be encrypted"
#define IS_PRINTABLE(c) (c > 0x1f && c < 0x7f)?c:'.'

using namespace cppcrypto;

/* The options we understand. */

enum alg_type_e{
	PRIME,
	DES,
	AES,
	KAL = 4,
	MD5 = 8,
	SHA256 = 16,
	KUPYNA = 32,
	ANONE = 64,
	EUCLID = 128
};
enum enc_flag_e{
	ENC,
	DEC,
	ENONE
};

static struct argp_option options[] = {
	{	"src-file",		'f',	"<path to file>",		0,		"source file with text message" },
	{	"dst-file",		'o',	"<path to file>",		0,		"file. to which messge wil be outputted" },
	{	"key",			'k',	"<key string>",			0,		"specify key, which will be aplied during encription/decription" },
	{	"number",		'n',	"<integer>",			0,		"specify number to check for primeness" },
	{	"encrypt",		'e',	0,						0,		"encrypt message" },
	{	"decrypt",		'd',	0,						0,		"decrypt message" },
	{	"d1",			'l',	"<integer>",			0,		"first figit for euclid" },
	{	"d2",			'h',	"<integer>",			0,		"sedond figit for euclid" },
	{	0,				't',	"<AES|DES|KAL|PRIME|MD5|SHA256|KUPYNA|EUCLID>",		0,		"alhorythm type" },
	{ 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments_s
{
  char 			*key;                
  int 			fd_src; 
  int 			fd_dst;
  int			numb;
  unsigned int	d1;
  unsigned int	d2;
  enc_flag_e	enc_flag;
  alg_type_e 	alg_type;
};
typedef struct arguments_s arguments_t;

/******************************************GLOBAL VARIABLES**************************************/
int inp_size;
char *inp_buf = NULL;
char *out_buf = NULL;
char *hash_buf = NULL;
char *key = NULL;

/*/****************************************static functions declaration**************************/
static void process_msg(block_cipher* obj, 
						char *inp, 
						char *out, 
						char *key, 
						const int size, 
						const enc_flag_e flag){
	
	int ccount = 0;
	int i;
	
	ccount = size/16;
	if(size%16)
		ccount++;
		
	for(i = 0; i < ccount; i++){
		
		if (flag == ENC){
			obj->init(key,cppcrypto::block_cipher::direction::encryption);
			obj->encrypt_block(inp + (i*16), out + (i*16)); 
		} else{
			obj->init(key,cppcrypto::block_cipher::direction::decryption);
			obj->decrypt_block(inp + (i*16), out + (i*16));
		}
	}
		
}
/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	
	struct stat fstats;
	int err = 0;
	int arg_size = 0;
	struct timeval tv;
	struct timezone tz;

	/* Get the input argument from argp_parse, which we
	know is a pointer to our arguments structure. */
	gettimeofday(&tv, &tz);
	arguments_t *arguments = (arguments_t*) state->input;
	if (!arguments->key){
		srandom(tv.tv_usec);
		arguments->key = malloc(1);
		*arguments->key = random();
	}

	switch (key)
	{
		case 'f':
			if ( (arguments->fd_src = open(arg, O_RDWR)) < 0 ){
				printf("ERROR: no such file: %s\n", arg);
				exit(-1);
			}
			
			stat(arg, &fstats);
			
			if(!fstats.st_size){
				printf("ERROR: %s file is empty. Nothing to encrypt/decrypt\n", arg);
				exit(-1);
			}

			inp_size = fstats.st_size;
			inp_buf = malloc(inp_size);
			err = read(arguments->fd_src, inp_buf, inp_size);
			
			if (err != fstats.st_size){
				printf("ERROR: filed to read file: %s\n", arg);
				exit(-1);
			}
			break;
		case 'k':
			arg_size = strlen(arg);
			
			if (arguments->key)
				free(arguments->key);
			
			arguments->key = malloc(arg_size);
			memcpy(arguments->key, arg, arg_size);
			break;
		case 'd':
			arguments->enc_flag = DEC;
			break;
		case 'e':
			arguments->enc_flag = ENC;
			break;
			
		case 't':
			if (!strcmp("AES", arg))
				arguments->alg_type = AES;
			else if (!strcmp("DES", arg))
				arguments->alg_type = DES;
			else if (!strcmp("KAL", arg))
				arguments->alg_type = KAL;
			else if (!strcmp("PRIME", arg))
				arguments->alg_type = PRIME;
			else if (!strcmp("MD5", arg))
				arguments->alg_type = MD5;
			else if (!strcmp("SHA256", arg))
				arguments->alg_type = SHA256;
			else if (!strcmp("KUPYNA", arg))
				arguments->alg_type = KUPYNA;
			else if (!strcmp("EUCLID", arg))
				arguments->alg_type = EUCLID;
			else{
				printf("ERROR: incorrect alhorythm type!\n please specify DES|AES|KAL\n", arg);
				exit(-1);
			}
			break;
		case 'n':
			arguments->numb = strtoul(arg, NULL, 10);
			break;
		case 'l':
			arguments->d1 = strtoul(arg, NULL, 10);
			break;
		case 'h':
			arguments->d2 = strtoul(arg, NULL, 10);
			break;

		default:
			break;
	}
	return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, 0, 0 };

static void print_bin(unsigned char *data, int data_len){
	
	int i, k = 1;
	char arr[9] = { 0 };
	
	printf("%08p: ", data);
	for ( i = 0; i < data_len; i++){
		
		arr[k - 1] = IS_PRINTABLE(data[i]), k++;
		printf("0x%02x ", data[i]);
		
		if (k == 8){
			k = 1;
			printf("|%s|\n%08p: ", arr, data + i);
			memset(arr, 0, 9);
		}
	}
	printf("|%s|\n", arr); fflush(stdout);
	
}

static int check_primness(int n){

	int i;
	int sqrt_n = sqrt(n);
	
	for(i = 2; i <= sqrt_n; i++){
		
		if (!(n%i))
			return 0;
	}
	
	return 1;
}

unsigned int euclid(unsigned int d1,unsigned int d2){
	
	while(d1 != d2){
		if(d1 > d2)
			d1 -= d2;
		else
			d2 -= d1;
	}
	
	return d1;
		
}
/*
 * usage <appname> [-f] <filepath> -d [<path/to/outp/file>] -k [<key>] -d [decrypt] -e [encrypt] -t [<des>|<aes128/192/256>|<kal128/256/512>]
 */
int main(int argc, char** argv){
	arguments_t arguments = {
		.key 		= 	NULL,
		.fd_src 	= 	0,
		.fd_dst 	= 	0,
		.numb		=   0,
		.d1			= 	0,
		.d2			=	0,
		.enc_flag 	= 	ENC,
		.alg_type 	= 	ANONE
	};
	
	/* Parse our arguments; 1every option seen by parse_opt will
	   be reflected in arguments. */
	argp_parse (&argp, argc, argv, 0, 0, &arguments);
		
	block_cipher *block = NULL;
	crypto_hash *hash = NULL;
	switch(arguments.alg_type){
		case PRIME:
			printf("number %d %s", arguments.numb, 
					check_primness(arguments.numb)?"is prime\n":"is not prime\n");
			return 0;
		case MD5:
			hash = new md5();
			break;
		case SHA256:
			hash = new sha256();
			break;
		case KUPYNA:
			hash = new kupyna(256);
			break;
		case AES:
			block = new rijndael128_256();
			break;
		case DES:
			block = new anubis256();
			break;
		case KAL:
			block = new kalyna128_256();
			break;
		case EUCLID:
			printf("LDT equals %d\n", euclid(arguments.d1, arguments.d2));
			return 0;
		default:
			printf("ERROR: incorect chipher type\n");
			return -1;
			break;
	}
	
	if (arguments.alg_type & (AES | DES | KAL)){
	
		out_buf = malloc(inp_size);
		process_msg(block, inp_buf, out_buf, arguments.key, inp_size,  ENC);

		printf("out_buf:\n");
		print_bin(out_buf, inp_size);

		memset(inp_buf, 0, inp_size);
		process_msg(block, out_buf, inp_buf, arguments.key, inp_size,  DEC);
		
		printf("inp_buf:\n", inp_buf);
		print_bin(inp_buf, inp_size);
	} else 	if (arguments.alg_type & (MD5 | SHA256 | KUPYNA)){
		hash_buf = malloc(32);
		memset(hash_buf, 0, 32);
		
		hash->hash_string(inp_buf, inp_size, hash_buf);
		printf("hash of specified file:");
		print_bin(hash_buf, 32);
	}
	
	return 0;
}
