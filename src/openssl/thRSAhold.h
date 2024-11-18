#pragma once

#include <openssl/evp.h>

EVP_PKEY* thRSAhold_init( char* path );

void thRSAhold_deinit( EVP_PKEY* key );

int thRSAhold_expected_ct_len( int pt_len );

int thRSAhold_encrypt( EVP_PKEY* pkey, unsigned char* pt, int pt_len, unsigned char* ct, int max_ct_len );