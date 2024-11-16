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
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#define MAX_CERT_VALIDITY_DAYS 9999999

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

// Gestionnaires de mémoire pour OpenSSL
struct X509Deleter {
    void operator()(X509* x) const { X509_free(x); }
};
struct X509StoreDeleter {
    void operator()(X509_STORE* s) const { X509_STORE_free(s); }
};
struct X509StoreCtxDeleter {
    void operator()(X509_STORE_CTX* ctx) const { X509_STORE_CTX_free(ctx); }
};

using X509_ptr = std::unique_ptr<X509, X509Deleter>;
using X509Store_ptr = std::unique_ptr<X509_STORE, X509StoreDeleter>;
using X509StoreCtx_ptr = std::unique_ptr<X509_STORE_CTX, X509StoreCtxDeleter>;

class CryptoUtils {
private:
    static void handleOpenSSLErrors();
    static void derive_key_from_user_key(std::vector<unsigned char> user_key, unsigned char* key, int key_len);
public:

    static std::vector<unsigned char> encryptSym(std::vector<unsigned char> plaintext, std::vector<unsigned char> user_key);
    static std::vector<unsigned char> decryptSym(std::vector<unsigned char> ciphertext, std::vector<unsigned char> user_key);

    /* Asym */
    static std::vector<unsigned char> rsa_decrypt(const std::vector<unsigned char>& cipherText, EVP_PKEY* priv_key);
    static std::vector<unsigned char> rsa_encrypt(const std::vector<unsigned char>& plainText, EVP_PKEY* pub_key);
    static EVP_PKEY_ptr generate_rsa_key(int keylen = 2048);
    static std::string get_pub_key(EVP_PKEY *priv_key);

    /**
     * Generates an X509 certificate.
     *
     * @param ca_key The private key of the certification authority (CA) used to sign the certificate.
     * @param ca_cert The certificate of the CA. If null, the generated certificate will be self-signed.
     * @param pub_key The public key to be associated with the generated certificate.
     * @param cn The Common Name (CN) field in the certificate subject.
     * @param organisation The Organization (O) field in the certificate subject.
     * @param country_code The Country (C) field in the certificate subject.
     * @param day_valid The number of days the certificate is valid for.
     * @return A unique pointer to the generated X509 certificate.
     * @throws std::runtime_error if any step in certificate generation or signing fails.
     */
    static X509_ptr generate_certificate(EVP_PKEY* ca_key, X509* ca_cert, EVP_PKEY* pub_key, const std::string& cn, const std::string& organisation, const std::string& country_code, int day_valid=MAX_CERT_VALIDITY_DAYS);
    static BioPtr certificate_to_bio(X509* cert);
    static std::vector<char> get_bio_to_pem(BIO* bio);

    /**
     * Checks the validity of a given certificate against an authority's certificate.
     *
     * @param cert The certificate to be checked.
     * @param authority The certificate of the authority against which the validity is checked.
     * @return True if the certificate is valid, otherwise false.
     * @throws std::runtime_error if creating or initializing the store or context fails, or
     *         if certificate verification fails due to invalid input or logic error.
     */
    static bool check_certificate_validity(X509* cert, X509* authority);
    static X509_ptr load_certificate(std::vector<char> pem_cert);

    static std::vector<unsigned char> signData(EVP_PKEY* priv_key, std::vector<char> data);
    static bool checkSignature(std::vector<char> data, std::vector<unsigned char> signature, X509* certificate);
};



#endif //CRYPTOUTILS_H
