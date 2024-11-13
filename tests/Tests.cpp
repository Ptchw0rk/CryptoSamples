//
// Created by patch on 13/11/24.
//

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include "Tests.h"
#include "CryptoUtils.h"



EVP_PKEY_ptr Tests::testPrivKeyGen() {
    EVP_PKEY_ptr key = CryptoUtils::generate_rsa_key(4096);
    CPPUNIT_ASSERT(key != nullptr);
    return key;
}

void Tests::testPubKeyGen() {
    EVP_PKEY_ptr priv_key = Tests::testPrivKeyGen();
    std::string pub_key = CryptoUtils::get_pub_key(priv_key.get());
    std::printf("Pub key : \n%s", pub_key.c_str());
}
void Tests::testCertGen() {}
void Tests::testSignData() {}
void Tests::testSymEncrypt() {}
void Tests::testSymDecrypt() {}
void Tests::testAsymEncrypt() {}
void Tests::testAsymDecrypt() {}

CPPUNIT_TEST_SUITE_REGISTRATION(Tests);