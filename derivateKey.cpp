#define _CRT_SECURE_NO_WARNINGS

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdexcept>




void error(const char* msg)
{
    throw  std::runtime_error(msg);
}

int EVPKeyderivation(const char* password, unsigned char* dkey, unsigned char* dIV, unsigned char* dsalt, int iter)
{
    EVP_KDF* kdf;
    EVP_KDF_CTX* kctx = NULL;
    unsigned char derived[48];
    OSSL_PARAM params[6], * p = params;

    /* Find and allocate a context for the HKDF algorithm */
    if ((kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL)) == NULL) {
        error("EVP_KDF_fetch");
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);    /* The kctx keeps a reference so this is safe */
    if (kctx == NULL) {
        error("EVP_KDF_CTX_new");
    }


    /* Build up the parameters for the derivation */
    char digest[] = "SHA256";
    int keylen = 48;
    *p++ = OSSL_PARAM_construct_utf8_string("digest", digest, (size_t)7);
    *p++ = OSSL_PARAM_construct_octet_string("salt", dsalt, (size_t)8);
    *p++ = OSSL_PARAM_construct_octet_string("pass", (void*)password, (size_t)strlen(password));
    *p++ = OSSL_PARAM_construct_int("keylen", &keylen);
    *p++ = OSSL_PARAM_construct_int("iter", &iter);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        error("EVP_KDF_CTX_set_params");
    }

    /* Do the derivation */
    if (EVP_KDF_derive(kctx, derived, sizeof(derived),p) <= 0) {
        error("EVP_KDF_derive");
    }
    memcpy(dkey, derived, 32);
    memcpy(dIV, derived + 32, 16);
    EVP_KDF_CTX_free(kctx);

    return 0;
}
