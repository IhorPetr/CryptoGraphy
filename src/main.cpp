#include <stdio.h>
#include <argp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "rijndael.h"
//#include "anubis.h"

#define INP_STR "This string should be encrypted"
#define ENCR_MSG(inp, outp, key, obj)	\
	obj->init(key,cppcrypto::block_cipher::direction::encryption); \
	obj->encrypt_block(inp, (unsigned char*) outp); 
#define DECR_MSG(inp, outp, key, obj)	\
	obj->init(key,cppcrypto::block_cipher::direction::decryption); \
	obj->decrypt_block(inp, (unsigned char*) outp);

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
			ENCR_MSG(inp + (i*16), out + (i*16), key, obj);
		} else
			DECR_MSG(inp + (i*16), out + (i*16), key, obj);
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
			block = new rijndael128_128();
			break;
		case DES:
			block = new rijndael128_128();
			break;
		case KAL:
			//block = new anubis128();
			break;
		default:
			break;
	}
	
	out_buf = malloc(inp_size);
	process_msg(block, inp_buf, out_buf, arguments.key, inp_size,  arguments.enc_flag);
	
	printf("out_buf = %s", out_buf);
	//save to file or output to console
	//save generated key to file or print to console
	
	return 0;
}
