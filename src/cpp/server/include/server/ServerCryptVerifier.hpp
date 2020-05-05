#ifndef SERVER_CRYPT_VERIFIER_HPP
#define SERVER_CRYPT_VERIFIER_HPP

/** Including c functions from DSP crypt ***/
extern "C" {    
	int verify_sign(const char *publickeyfile,const char *msg, char *signature); 
	int Base64Decode(char* b64message, unsigned char** buffer, size_t* length); 
	int Base64Encode(const unsigned char* buffer, char** b64message);
};
#define HEADER_KEY_USER "x-user"
#define HEADER_KEY_SIGNED_DATE "x-signed-date"
#define HEADER_KEY_SIGNATURE "x-signature"
#define HEADER_KEY_RANDOM "x-random"
#define HEADER_KEY_USER_INFO "x-user-info"
#define ENV_SIGN_PUB_KEY_FILE "auth_verifysign_publickey_cert"

#endif
