#ifndef DSPCRYPTVERIFIER_H
#define DSPCRYPTVERIFIER_H

#include <string.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <assert.h> 
#include <openssl/evp.h> 
#include <openssl/pem.h> 

int verify_sign(const char *publickeyfile,const char *msg, char *signature); 
int Base64Decode(char* b64message, unsigned char** buffer, size_t* length); 
int Base64Encode(const unsigned char* buffer, char** b64message);

#define SIGNATURE_LENGTH 256
#define SIGNATURE_ALGO "SHA256"

#endif
