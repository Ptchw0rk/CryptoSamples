//
// Created by patch on 13/11/24.
//

#ifndef CRYPTOUTILS_H
#define CRYPTOUTILS_H

#include <memory>
#include <string>
#include <vector>
#include <openssl/types.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

struct EVP_PKEY_deleter {
    void operator()(EVP_PKEY* evp_pkey) const {
        EVP_PKEY_free(evp_pkey);
    }
};
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_deleter>;

struct BIODeleter {
    void operator()(BIO* bio) const {
        BIO_free(bio);
    }
};
using BioPtr = std::unique_ptr<BIO, BIODeleter>;

class CryptoUtils {
private:
    static void handleOpenSSLErrors();
    static void derive_key_from_user_key(const std::string& user_key, unsigned char* key, int key_len);
public:

    static std::string encryptSym(const std::string& plaintext, const std::string& user_key);
    static std::string decryptSym(const std::string& ciphertext, const std::string& user_key);
    static std::vector<unsigned char> rsa_decrypt(const std::vector<unsigned char>& cipherText, EVP_PKEY* pkey);
    static std::vector<unsigned char> rsa_encrypt(const std::vector<char> plainText, EVP_PKEY* pkey);
    static EVP_PKEY_ptr generate_rsa_key(int keylen = 2048);
    static std::string get_pub_key(EVP_PKEY *priv_key);
};



#endif //CRYPTOUTILS_H
