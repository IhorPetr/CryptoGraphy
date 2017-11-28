#include <stdio.h>
#include <argp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "rijndael.h"
#include "anubis.h"
#include "kalyna.h"

#define INP_STR "This string should be encrypted"
#define IS_PRINTABLE(c) (c > 0x1f && c < 0x7f)?c:'.'

using namespace cppcrypto;

/* The options we understand. */

enum alg_type_e{
	DES,
	AES,
	KAL,
	ANONE
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
	{	"encrypt",		'e',	0,						0,		"encrypt message" },
	{	"decrypt",		'd',	0,						0,		"decrypt message" },
	{	0,				't',	"<AES|DES|KAL>",		0,		"alhorythm type" },
	{ 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments_s
{
  char 			*key;                
  int 			fd_src; 
  int 			fd_dst;
  enc_flag_e	enc_flag;
  alg_type_e 	alg_type;
};
typedef struct arguments_s arguments_t;

/******************************************GLOBAL VARIABLES**************************************/
int inp_size;
char *inp_buf = NULL;
char *out_buf = NULL;
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
	
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  arguments_t *arguments = (arguments_t*) state->input;

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
			else{
				printf("ERROR: incorrect alhorythm type!\n please specify DES|AES|KAL\n", arg);
				exit(-1);
			}
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

/*
 * usage <appname> [-f] <filepath> -d [<path/to/outp/file>] -k [<key>] -d [decrypt] -e [encrypt] -t [<des>|<aes128/192/256>|<kal128/256/512>]
 */
int main(int argc, char** argv){
	arguments_t arguments = {
		.key 		= 	0,
		.fd_src 	= 	0,
		.fd_dst 	= 	0,
		.enc_flag 	= 	ENC,
		.alg_type 	= 	AES
	};
	
	/* Parse our arguments; every option seen by parse_opt will
	   be reflected in arguments. */
	argp_parse (&argp, argc, argv, 0, 0, &arguments);
		
	block_cipher *block = NULL;
	switch(arguments.alg_type){
		case AES:
			block = new rijndael128_256();
			break;
		case DES:
			block = new anubis256();
			break;
		case KAL:
			block = new kalyna128_256();
			break;
		default:
			printf("ERROR: incorect chipher type\n");
			return -1;
			break;
	}
	
	out_buf = malloc(inp_size);
	process_msg(block, inp_buf, out_buf, arguments.key, inp_size,  ENC);

	printf("out_buf:\n");
	print_bin(out_buf, inp_size);

	memset(inp_buf, 0, inp_size);
	process_msg(block, out_buf, inp_buf, arguments.key, inp_size,  DEC);
	
	printf("inp_buf:\n", inp_buf);
	print_bin(inp_buf, inp_size);

	//save to file
	//save generated key to file or print to console
	
	return 0;
}
