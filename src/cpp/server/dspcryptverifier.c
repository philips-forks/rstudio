/*
 * dspcryptverifier.c
 *
 * Copyright (C) Koninklijke Philips Electronics N.V. 2017
 *
 * Unless you have received this program directly from Philips pursuant
 * to the terms of a commercial license agreement with Philips, then
 * this program is licensed to you under the terms of version 3 of the
 * GNU Affero General Public License. This program is distributed WITHOUT
 * ANY EXPRESS OR IMPLIED WARRANTY, INCLUDING THOSE OF NON-INFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Please refer to the
 * AGPL (http://www.gnu.org/licenses/agpl-3.0.txt) for more details.
 *
 */
#include <server/dspcryptverifier.h>
/*
int verify_sign(const char *publickeyfile,const char *msg, char *signature); 
int SIGNATURE_LENGTH = 256;
static const char SIGNATURE_ALGO[] = "SHA256";
*/

/**
 * Reads the public key from the pem file
 *
 * @filename : Name of the public pem file
 *
 * @returns NULL on failure to read.
 **/
EVP_PKEY * createKeyWithFileName(char * filename)	{

	EVP_PKEY *pkey = EVP_PKEY_new();
        FILE *fp = fopen(filename, "rb");
        if (fp == NULL){
        	printf("Unable to open file %s \n",filename);
        	return NULL;    
        }
        pkey = PEM_read_PUBKEY(fp, &pkey, NULL, NULL);
        return pkey;
}

void writeToFile(const char *msg,const char *field1,const char* field2 )	{
        FILE *fp = fopen("/var/log/sriram.txt", "a");
        if (fp == NULL){
                printf("Unable to open file \n");
                return ;
        }
	fprintf(fp, msg, field1,field2);
    	fclose(fp);

}

/**
 * Calculates the decode length of the string
 *
 * @base64input  takes the base64 input and calculates the length
 *
 */
size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
        size_t len = strlen(b64input),
                padding = 0;

        if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
                padding = 2;
        else if (b64input[len-1] == '=') //last char is =
                padding = 1;

        return (len*3)/4 - padding;
}



/**
 * Base64 decoding of the message.
 *
 * @b64Message contains the base 64 encoded message
 *
 * @buffer outputs the decoded message pointer
 *
 * length  output length of decoded message
 *
 **/
int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) {
//Decodes a base64 encoded string
        BIO *bio, *b64;

	printf ("encoded data %s\n", b64message);
	writeToFile("####################To #Encode data = %s \n",b64message,"");
        int decodeLen = calcDecodeLength(b64message);
        *buffer = (unsigned char*)malloc(decodeLen + 1);
        (*buffer)[decodeLen] = '\0';

        bio = BIO_new_mem_buf(b64message, -1);
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
        *length = BIO_read(bio, *buffer, strlen(b64message));
	writeToFile("####################To #decode data = %s \n",*buffer,"");
	printf ("decoded data %s\n", *buffer);
        assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
        BIO_free_all(bio);

        return (0); //success
}

/**
 * Base64 encoding of the message
 *
 * @buffer to be encoded text
 *
 * @length Length of the encoded message
 *
 * @b64message Base64 encoded message returned.
 *
 **/
int Base64Encode(const unsigned char* buffer, char** b64message) { //Encodes a binary safe base 64 string
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;
	size_t length = strlen(buffer);
	writeToFile("####################To #Encode data = %s \n",buffer,"");
        writeToFile("####################To #Base64 message = %s \n",b64message,"");
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	*b64message = (char*) malloc((bufferPtr->length + 1) * sizeof(char));
	memcpy(*b64message, bufferPtr->data, bufferPtr->length);
	*b64message[bufferPtr->length] = '\0';
	BIO_free_all(bio);

//	*b64message=(*bufferPtr).data;

//	writeToFile("#####################Encoded data = %s \n",*b64message,"");
	return (0); //success
}



/**
 * Verifies the signature passed as input with the message signed.
 *
 * @publickeyfile : Public key pem to be used for verifying the signature
 *
 * @bmsg : base64 encoded message to be validated against for signature
 *
 * @bsignature : base64 encoded signature of type sha256.
 *
 **/
int verify_sign(const char *publickeyfile, const char *bmsg, char *bsignature) {
    EVP_MD_CTX      *ctx;
    size_t          sig_len;
    int             bool_ret;

   unsigned char *msg;
   unsigned char *signature;
   size_t *msg_len;
   size_t *slen;
   OpenSSL_add_all_algorithms();
   EVP_PKEY *pkey = createKeyWithFileName(publickeyfile);

   //writeToFile("Key File =\n%s\n",publickeyfile,"");
	
   if (Base64Decode(bsignature,&signature,&slen) !=0)	{
	printf(" Invalid signature to parse");
	return EXIT_FAILURE;

   }
   //writeToFile("Signture =\n%s\n",signature,"");
   //writeToFile("bdata =\n%s\n",bmsg,"");
   if(Base64Decode(bmsg,&msg,&msg_len) !=0)	{
	printf(" Invalid data to parse.Not a valid base64 format.");
	return EXIT_FAILURE;
   }
   ctx = NULL;
   //writeToFile("data =\n%s\n",msg,"");
   
   ctx = EVP_MD_CTX_create();    
   const EVP_MD* md = EVP_get_digestbyname(SIGNATURE_ALGO);

   EVP_DigestInit_ex( ctx, md, NULL );
   EVP_DigestVerifyInit( ctx, NULL, md, NULL, pkey );


   EVP_DigestVerifyUpdate(ctx,msg, msg_len);

   //verifies the signature against the data passed. returns failure
   // in case it is a bad signature
   if ( !EVP_DigestVerifyFinal( ctx, signature, SIGNATURE_LENGTH )) {
	printLastError("Public verification failed");
	return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

}

/**
 * Prints the error related to the cryptography
 *
 * @errMsg : Error messages to be suffixed.
 *
 *
 */
void printLastError(char *msg){

	char * err = malloc(130);
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	printf("%s ERROR: %s\n",msg, err);
	free(err);

}
void help(){ 
        printf("\n"); 
        printf("Usage :\n"); 
        printf("eg:\n"); 
        printf("<<EXENAME>> PUBLICKEYFILE SIGNEDDATAFILE\n\n"); 
} 
/*
int main(int argc, char **argv) 
{
	if (argc<3){ 
		help(); 
		return 1; 
	} 
	unsigned char *signedData; 
	unsigned char *bsignedData; 
	EVP_PKEY *key; 
	unsigned char *data; 
	char *decryptedData;
	printf("Reading the key from file....");
	printf("\n");
	key = argv[1];
	printf("Reading the signed data from file....");
	printf("\n");
	signedData = (unsigned char *)argv[2];
		
	printf("Reading the data from file....");
	printf("\n");
        data       = (unsigned char *)argv[3];
	printf("verifying the signature.......");
	printf("\n");
        int result = verify_sign(key,data,signedData);


	printf(" Verified ::%d", result);
	
}
*/
