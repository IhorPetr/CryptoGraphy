#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "rsa.h"

uint p, q, e, d, n;

uint paddingNumber = 0;

uint ModAdd(uint a, uint b, byte op, uint mod) {
	uint result = 0;
	if (op == '+'){
		if (a + b <= a || a + b <=b ){
			result = a - ( mod - b );
		} else if (a + b <= mod){
			result = a + b;
		} else {
			result = a + b - mod;
		} 
		return result;
	}
	else {
		if (b > a){
			uint tmp = b - a;
			while (tmp >= mod) tmp -= mod;
			result = mod - tmp;
			return result;
		} else {
			result = a - b;
			while (result >= mod) result -= mod;
			return result;
		}
	}
}

uint ModMul(uint x, uint y, uint mod) {
	uint tmp,tmp2;
	uint previous;
	uint result = 0;
	uint cnt = 1;

	while ( x >= 1 ) {

	    tmp = (x & 1); 

	    if (tmp == 1){

	        if (cnt == 1) {
	     		while ( y >= mod ) y -= mod;
	            result = y;
	        } 
	        else {
	            previous = y;
	            tmp2 = cnt;

	            while (tmp2 != 1){
	                if (previous + previous < previous){
	                    previous = previous - ( mod - previous );
	                } else if (previous + previous <= mod){
	                    previous = previous + previous;
	                } else {
	                    previous = ModAdd(previous,previous,'+',mod);
	                }
	                
	                tmp2 >>= 1;
	            }
	            if (result + previous <= result){
	                result = result - ( mod - previous );
	            } else if (result + previous <= mod){
	                result = result + previous;
	            } else {
	                result = ModAdd(result,previous,'+',mod);
	            }
	            
	        }
	    }
	    x >>= 1;
		cnt <<= 1;
	} 
	return result;
}


uint ModPow(uint base, uint exp, uint mod) {
	uint result = 1;
	uint tmp = base;

	for ( ; ; exp >>= 1) {
		if (exp <= 0){
			while (result >= mod) result -= mod;
			return result;
		}
		if ((exp & 1) == 1){
			result = ModMul(result,tmp,mod);
		}
		tmp = ModMul(tmp,tmp,mod);
	} 
}

bool IsPrime(uint testNum, uint repeat) {
	uint result = testNum - 1;
	uint randomNum,tmp,modResult;

	if (( testNum != 2 && (testNum & 1) == 0) || (testNum < 2)) return FALSE;

	while ( (result & 1) == 0) result >>= 1;

	while (repeat--){

		tmp = result;
		randomNum = (uint)((double)WELLRNG512a())*testNum + 1;
		while (randomNum >= (testNum - 1))  randomNum -= (testNum - 1);
		randomNum += 1;
		modResult = ModPow(randomNum,tmp,testNum);

		while (tmp != testNum - 1 && modResult != testNum - 1 && modResult != 1){
			modResult = ModMul(modResult, modResult, testNum);
			tmp <<= 1;
		}
		if (modResult != testNum - 1 && (tmp & 1) == 0) return FALSE;
	} 
	return TRUE;
}

uint GCD(uint a, uint b) {
	uint prev_a;
	while(b != 0) {
		printf("GCD(%u, %u)\n", a, b);
		prev_a = a;
		a = b;
		while(prev_a >= b) prev_a -= b;
		b = prev_a;
	}
	printf("GCD(%u, %u)\n\n", a, b);
	return a;
}


uint ModInv(uint a, uint m) {
	uint x,x1,x2;
	uint quotient;
	uint t,t1 = 0;
	uint tmp1,tmp2,quotientTmp;
	int result = 1;

	for (x1 = a, x2 = m; x1 != 1; x2 = x1, x1 = x){
		tmp1 = x2;
		tmp2 = x1;
		quotientTmp = 0;
		while (tmp1 >= tmp2){
			quotientTmp ++;
			tmp1 -= tmp2;
		} 
		quotient = quotientTmp;

		x = x2 - x1*quotient;
		t = t1 - result*quotient;
		t1 = (uint)result;
		result = t;
	}
	if (result < 0) result += m;
	
	return (uint)result;
}

void MRSAKeygen(uint *p, uint *q, uint *e, uint *d, uint *n) {

	while (TRUE){
		while (TRUE){
		    *p = (uint)((double)WELLRNG512a()*(65536 - 46340 + 1)) + 46340;
		    printf("random-number1 %d selected.\n",*p);
			if (IsPrime(*p,10)) {
				printf("%d may be Prime.\n\n",*p);
				break;
			}
			printf("%d is not Prime.\n\n",*p);
		}
		while (TRUE){
			*q = (uint)((double)WELLRNG512a()*(65536 - 46340 + 1)) + 46340;
			printf("random-number2 %d selected.\n",*q);
			if (*q == *p) continue;
			 if (IsPrime(*q,10)) {
				printf("%d may be Prime.\n\n",*q);
				break;
			}
			printf("%d is not Prime.\n\n",*q);
		}
		*n = (*p)*(*q);
		if (*n >= 2147483648 && *n <= 4294967295){
			printf("finally selected prime p, q = %u %u.\nthus, n = %u\n\n",*p,*q,*n);
			uint pi_n = (*p - 1)*(*q - 1);
			while (TRUE){
				*e = ((uint)((double)WELLRNG512a() * (pi_n  - 1) + 2));
				printf("e : %u selected.\n",*e);
				if (GCD(*e,pi_n) == 1) break;
			}
			*d = ModInv(*e,pi_n);
			printf("d : %u selected.\n\n",*d);
			printf("e d n pi_n : %u %u %u %u\n",*e,*d,*n,pi_n);
			printf("e*d mod pi_n : %u\n\n",ModMul(*e,*d,pi_n));
			break;
		}
		printf("=========================== < n is not 32bit > ===========================\n\n");
	}
}



uint FindNBit(uint x ){
  uint ans = 0 ;
  while( x>>=1 ) ans++;
  return ans + 1;
}

uint MRSACipher(FILE *ifp, uint len, FILE *ofp, uint key, uint n) {
	uint tmpText = 0;
	uint result = 0;
	uint modBit = FindNBit(n); 
	uint paddingCnt = (((len&3) == 0) ? 0 : (4 - (len&3)) );
	
	len += paddingCnt; 

	char *byte_of_file_data = (char *)malloc(sizeof(char)*(len));
	char *bit_of_file_data = (char *)malloc(sizeof(char)*(len*8));
	char *buffer = (char *)malloc(sizeof(char)*4);
	bzero(byte_of_file_data,len);
	bzero(bit_of_file_data,len*8);
	

	fread(byte_of_file_data,len - paddingCnt,1,ifp);
	

	if (paddingCnt) {
		paddingNumber = paddingCnt;
		for (uint i = len - 1; i >= len - paddingCnt; i --){
			byte_of_file_data[i] = '0';
		}
	}

	/* String_To_Bit */
	for (uint i = 0; i < len; i ++){
		for (uint j = 8; j >= 1; j --){
			*(bit_of_file_data + ( i * 8 ) + ( 8 - j )) = (( *(byte_of_file_data + i) & (0x01 << ( j - 1 ))) >> ( j - 1 ));
		}
	}
	printf("MRSACipher start. file len is %u\n\n",len-paddingCnt);

	for (uint i = 0; i < (len>>2); i ++){

		tmpText = 0;
		bzero(buffer,4);

		printf("len : %u\n",len-paddingCnt-i*4);
		for (uint j = 0; j < 4; j ++){
			*(buffer + j) = *(byte_of_file_data + i*4 + j );
		}
		printf("buf : %s\n",buffer);

		/* Bit_To_Uint */
		for (uint j = 0; j < modBit; j ++){
			tmpText |= (*(bit_of_file_data + (i*modBit) + j) << (modBit - j - 1));
		}
		printf("ptx : %u\n",tmpText);

		if (tmpText > n) {
			printf("Error Encryption / Decryption to overflow\n");
		}

		/* Encryption OR Decryption */
		tmpText = ModPow(tmpText,key,n);
		printf("ctx : %u\n",tmpText);

		/* Uint_To_Bit */
		for (uint j = 0; j < modBit; j ++){
			*(bit_of_file_data + (i*modBit) + j) = (tmpText & (0x01 << (modBit - j - 1))) >> (modBit - j - 1);
		}

		result += 4; 
		putchar('\n');
	}
	bzero(byte_of_file_data,len); 
	
	/* Bit_To_String */
	for (uint i = 0; i < len; i ++){
		for (uint j = 8; j >= 1; j --){
			*(byte_of_file_data + i) |= ( *(bit_of_file_data + ( i * 8 ) + ( 8 - j )) << ( j - 1 ));
		}
	}

	fwrite(byte_of_file_data,1,len,ofp);
	

	free(buffer);
	free(bit_of_file_data);
	free(byte_of_file_data);
	
	return result;
}

void deletePadding(FILE *ofp,uint fsize){
	fseek(ofp,fsize-paddingNumber,SEEK_SET);
	while (paddingNumber--){
		fwrite(" ",1,1,ofp);
	}
	
}

int main(int argc, char const *argv[]) {
	uint seed = time(NULL);
	InitWELLRNG512a(&seed);
	
	FILE *data_fp, *enc_fp, *dec_fp;
	uint fsize;
	
	if(argc != 4) {
		printf("usage : ./rsa data_file encrypt_file decrypt_file\n");
		exit(1);
	}

	data_fp = fopen(argv[1], "rb");
	enc_fp = fopen(argv[2], "wb");
	if(data_fp == NULL | enc_fp == NULL) {
		printf("file open fail\n");
		exit(1);
	}

	fseek(data_fp, 0, SEEK_END);
	fsize = ftell(data_fp);
	printf("data file size : %u\n\n", fsize);
	fseek(data_fp, 0, SEEK_SET);
	
	MRSAKeygen(&p, &q, &e, &d, &n);
	
	fsize = MRSACipher(data_fp, fsize, enc_fp, e, n);

	fclose(data_fp);
	fclose(enc_fp);
	
	enc_fp = fopen(argv[2], "rb");
	dec_fp = fopen(argv[3], "wb");
	if(dec_fp == NULL | enc_fp == NULL) {
		printf("file open fail\n");
		exit(1);
	}

	printf("encrypted file size : %u\n\n", fsize);

	fsize = MRSACipher(enc_fp, fsize, dec_fp, d, n);

	deletePadding(dec_fp,fsize);
	
	
	fclose(enc_fp);
	fclose(dec_fp);
	
	return 0;
}