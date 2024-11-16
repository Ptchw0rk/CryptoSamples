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

void Tests::testExportLoadCert() {
    EVP_PKEY_ptr ca = Tests::testPrivKeyGen();
    EVP_PKEY_ptr user_key = Tests::testPrivKeyGen();
    X509_ptr root_ca = CryptoUtils::generate_certificate(ca.get(), nullptr, ca.get(), "testor_authority", "test_org", "XX", MAX_CERT_VALIDITY_DAYS);
    X509_ptr user_cert = CryptoUtils::generate_certificate(ca.get(), root_ca.get(), user_key.get(), "testor", "test_org", "XX", MAX_CERT_VALIDITY_DAYS);
    std::vector<char> root_ca_pem = CryptoUtils::get_bio_to_pem(CryptoUtils::certificate_to_bio(root_ca.get()).get());
    std::vector<char> user_pem = CryptoUtils::get_bio_to_pem(CryptoUtils::certificate_to_bio(user_cert.get()).get());

    X509_ptr root_ca_loaded(CryptoUtils::load_certificate(root_ca_pem));
    X509_ptr user_cert_loaded(CryptoUtils::load_certificate(user_pem));

    CPPUNIT_ASSERT(CryptoUtils::check_certificate_validity(user_cert_loaded.get(), root_ca_loaded.get()));
}
void Tests::testSignData() {
    EVP_PKEY_ptr user_key = Tests::testPrivKeyGen();
    X509_ptr user_cert = CryptoUtils::generate_certificate(user_key.get(), nullptr, user_key.get(), "testor", "test_org", "XX", MAX_CERT_VALIDITY_DAYS);

    EVP_PKEY_ptr wrong_key = Tests::testPrivKeyGen();
    X509_ptr wrong_cert = CryptoUtils::generate_certificate(wrong_key.get(), nullptr, wrong_key.get(), "testor", "test_org", "XX", MAX_CERT_VALIDITY_DAYS);

    EVP_PKEY_ptr wrong_child_key = Tests::testPrivKeyGen();
    X509_ptr wrong_child_cert = CryptoUtils::generate_certificate(user_key.get(), user_cert.get(), wrong_key.get(), "testor", "test_org", "XX", MAX_CERT_VALIDITY_DAYS);
    std::string data_str = "123456";
    std::vector<char> data(data_str.begin(), data_str.end());
    std::vector<unsigned char> sig = CryptoUtils::signData(user_key.get(), data);

    CPPUNIT_ASSERT(CryptoUtils::checkSignature(data, sig, user_cert.get()));
    CPPUNIT_ASSERT(CryptoUtils::checkSignature(data, sig, wrong_cert.get()) == false);

}

void Tests::testAsymEncrypt() {
    EVP_PKEY_ptr user_key = Tests::testPrivKeyGen();
    EVP_PKEY_ptr wrong_key = Tests::testPrivKeyGen();

    std::string data_str = "123456";
    std::vector<unsigned char> data(data_str.begin(), data_str.end());

    std::vector<unsigned char> cipherText = CryptoUtils::rsa_encrypt(data, user_key.get());
    std::vector<unsigned char> decrypted = CryptoUtils::rsa_decrypt(cipherText, user_key.get());

    std::vector<unsigned char> decrypted_wrong = CryptoUtils::rsa_decrypt(cipherText, wrong_key.get());
    CPPUNIT_ASSERT(decrypted == data);
    CPPUNIT_ASSERT(decrypted_wrong != data);
}

void Tests::testSymEncrypt() {
    std::string data_str = "123456";
    std::string key_str = "abcdef";
    std::string wrong_key_str = "edfsgersfg";
    std::vector<unsigned char> data(data_str.begin(), data_str.end());
    std::vector<unsigned char> key(key_str.begin(), key_str.end());
    std::vector<unsigned char> wrong_key(wrong_key_str.begin(), wrong_key_str.end());
    std::vector<unsigned char> encrypted = CryptoUtils::encryptSym(data, key);
    std::printf("Encrypted : \n");
    for(unsigned char e : encrypted) {
        std::printf("%x", e);
    }
    std::printf("\n");

    // Check valid key
    std::vector<unsigned char> decrypted = CryptoUtils::decryptSym(encrypted, key);
    CPPUNIT_ASSERT(data == decrypted);

    // Check invalid key
    bool valid = false;
    try {
        std::vector<unsigned char> wrong_decrypted = CryptoUtils::decryptSym(encrypted, wrong_key);
        CPPUNIT_ASSERT(data != wrong_decrypted);
    } catch(std::runtime_error& e) {
        std::string err = e.what();
        valid = err.find("Wrong key or invalid data to decrypt") == 0;
    }
    CPPUNIT_ASSERT(valid);

}

CPPUNIT_TEST_SUITE_REGISTRATION(Tests);