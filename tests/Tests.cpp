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
void Tests::testCertGen() {
    EVP_PKEY_ptr ca = Tests::testPrivKeyGen();
    EVP_PKEY_ptr user_key = Tests::testPrivKeyGen();

    X509_ptr cert = CryptoUtils::generate_certificate(ca.get(), nullptr, user_key.get(), "testor", "test_org", "XX");

    BioPtr bio = CryptoUtils::certificate_to_bio(cert.get());

    std::vector<char> pem_cert = CryptoUtils::get_bio_to_pem(bio.get());
    std::printf("Certificate PEM : \n%s", pem_cert.data());
}

void Tests::testCertCheck() {
    EVP_PKEY_ptr ca = Tests::testPrivKeyGen();
    EVP_PKEY_ptr user_key = Tests::testPrivKeyGen();

    X509_ptr root_ca = CryptoUtils::generate_certificate(ca.get(), nullptr, ca.get(), "testor_authority", "test_org", "XX", MAX_CERT_VALIDITY_DAYS);
    std::printf("Root CA : \n%s", CryptoUtils::get_bio_to_pem(CryptoUtils::certificate_to_bio(root_ca.get()).get()).data());
    X509_ptr user_cert = CryptoUtils::generate_certificate(ca.get(), root_ca.get(), user_key.get(), "testor", "test_org", "XX", MAX_CERT_VALIDITY_DAYS);
    std::printf("User cert : \n%s", CryptoUtils::get_bio_to_pem(CryptoUtils::certificate_to_bio(user_cert.get()).get()).data());

    CPPUNIT_ASSERT(CryptoUtils::check_certificate_validity(user_cert.get(), root_ca.get()));
}
void Tests::testSignData() {}
void Tests::testSymEncrypt() {}
void Tests::testSymDecrypt() {}
void Tests::testAsymEncrypt() {}
void Tests::testAsymDecrypt() {}

CPPUNIT_TEST_SUITE_REGISTRATION(Tests);