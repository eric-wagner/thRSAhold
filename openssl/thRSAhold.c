#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/decoder.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "thRSAhold.h"

#define RSA_KEYSIZE 2048/8 // fixed RSA keysize of 2048 bit
#define AES_KEYSIZE 16
#define IV_SIZE 12
#define MAC_SIZE 16
#define MIN_PADDING_LEN 11

/*void print_bytes(unsigned char* bytes, int len){

    for(int i=0; i<len; i++){
        printf("%02X:", bytes[i]);
    }
    printf("\n");

}*/

EVP_PKEY* thRSAhold_init( char* path ){

    FILE* fp = fopen ( path , "rb" );
    if( !fp ){
        printf("Couldn't open file");
        return 0;
    }

    OSSL_DECODER_CTX* dctx;
    EVP_PKEY* pkey = NULL;
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, "RSA", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
    if (dctx == NULL) {
        printf("Couldn't not create OSSL decoder");
        return 0;
    }
    

    if (!OSSL_DECODER_from_fp(dctx, fp)) {
        printf("Failed to decode key");
        return 0;
    }
    
    fclose(fp);

    //BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
    //EVP_PKEY_print_public(bp, pkey, 1, NULL);

    OSSL_DECODER_CTX_free(dctx);

    return pkey;
}

void thRSAhold_deinit( EVP_PKEY* key){
    EVP_PKEY_free(key);
}


int thRSAhold_expected_ct_len( int pt_len ){

    int padding_len = 0;
    padding_len = RSA_KEYSIZE - pt_len;
    if(padding_len < MIN_PADDING_LEN){
        padding_len = MIN_PADDING_LEN;
    }

    if(padding_len + pt_len == RSA_KEYSIZE){
        return RSA_KEYSIZE;
    } else if(padding_len + pt_len > RSA_KEYSIZE){
        return padding_len + pt_len + AES_KEYSIZE + MAC_SIZE;
    } else {
        printf("Error computing ciphertext length");
    }

    return -1;
}

int thRSAhold_encrypt( EVP_PKEY* pkey, unsigned char* pt, int pt_len, unsigned char* ct, int max_ct_len ){
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) {
        printf("EVP_PKEY_CTX_new() failed.");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if( !EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) ){
        printf("Setting RSA padding failed.");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if( !EVP_PKEY_encrypt_init_ex(ctx, NULL) ){
        printf("EVP_PKEY_encrypt_init_ex() failed.");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    int ct_len = thRSAhold_expected_ct_len(pt_len);

    if (ct_len == RSA_KEYSIZE){

        size_t rsa_len=ct_len;
        int ret = EVP_PKEY_encrypt(ctx, ct, &rsa_len, pt, pt_len);
        if ( ret !=1 ) {
            printf("EVP_PKEY_encrypt() failed.\n");
            printf("Error Code: %d\n", ret);
            ERR_print_errors_fp(stdout);
            EVP_PKEY_CTX_free(ctx);
            return ret;
        }

        if ( rsa_len != RSA_KEYSIZE ) {
            printf("Unexpected RSA ciphertext length (%zu vs %d)\n", rsa_len, RSA_KEYSIZE);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }

        return 1;

    } else {

        unsigned char aes_key[AES_KEYSIZE];
        FILE* urandom_fd = fopen("/dev/urandom", "r");
        if ( fread(aes_key, 1, AES_KEYSIZE, urandom_fd) < 0 ){
            printf("Error generating AES key\n");
        }

        unsigned char iv[IV_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

        unsigned char temp[pt_len + AES_KEYSIZE];
        memcpy(temp, aes_key, AES_KEYSIZE);
        memcpy(temp+AES_KEYSIZE, pt, pt_len + AES_KEYSIZE);

        size_t rsa_len = RSA_KEYSIZE;
        int ret = EVP_PKEY_encrypt(ctx, ct, &rsa_len, temp, RSA_KEYSIZE - MIN_PADDING_LEN);
        if ( ret !=1 ) {
            printf("EVP_PKEY_encrypt() failed.\n");
            printf("Error Code: %d\n", ret);
            ERR_print_errors_fp(stdout);
            EVP_PKEY_CTX_free(ctx);
            return ret;
        }
        if ( rsa_len != RSA_KEYSIZE ) {
            printf("Unexpected RSA ciphertext length (%zu vs %d)\n", rsa_len, RSA_KEYSIZE);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }
        
        EVP_CIPHER_CTX* symctx = EVP_CIPHER_CTX_new();
        if(1 !=EVP_EncryptInit_ex2(symctx, EVP_aes_128_gcm(), aes_key, iv, NULL) ){
            printf("EVP_EncryptInit_ex2() failed! \n");
            return 0;
        }

        int aes_len;
        if(1 != EVP_EncryptUpdate(symctx, ct + RSA_KEYSIZE, &aes_len, &(temp[RSA_KEYSIZE-MIN_PADDING_LEN]), pt_len + AES_KEYSIZE - RSA_KEYSIZE+MIN_PADDING_LEN )){
            printf("EVP_EncryptUpdate() failed! \n");
            EVP_CIPHER_CTX_free(symctx);
            return 0;
        }

        int tag_len;
        if (!EVP_EncryptFinal_ex(symctx, ct + RSA_KEYSIZE + aes_len, &tag_len)) {
            printf("EVP_EncryptFinal_ex() failed! \n");
            EVP_CIPHER_CTX_free(symctx);
            return 0;
        }

        if(1 != EVP_CIPHER_CTX_ctrl(symctx, EVP_CTRL_GCM_GET_TAG, 16, ct + RSA_KEYSIZE + aes_len)){
            printf("EVP_CIPHER_CTX_ctrl() failed! \n");
            EVP_CIPHER_CTX_free(symctx);
            return 0;
        }

        EVP_CIPHER_CTX_free(symctx);
    }

    return 1;
}