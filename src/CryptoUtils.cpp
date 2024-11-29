//
// Created by patch on 13/11/24.
//

#include "CryptoUtils.h"
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <cstring>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <variant>
#include <vector>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

void CryptoUtils::handleOpenSSLErrors() {
    unsigned long errCode;
    while ((errCode = ERR_get_error())) {
        char *err = ERR_error_string(errCode, nullptr);
        std::cerr << "Error: " << err << std::endl;
    }
    ERR_clear_error();
    throw std::runtime_error("OpenSSL error");
    abort();
}

/**
 * Derives a fixed-length key from a user-provided key using the SHA-256 hash
 * function. The resulting key will be the specified length in bytes, truncated
 * if necessary.
 *
 * @param user_key The user-provided key from which to derive the fixed-length
 * key.
 * @param key A pointer to an array of unsigned characters where the derived key
 * will be stored.
 * @param key_len The length of the derived key in bytes.
 */
void CryptoUtils::derive_key_from_user_key(std::vector<unsigned char> user_key, unsigned char *key, int key_len) {
    // Utiliser SHA-256 pour générer une clé de longueur fixe
    //unsigned char hash[SHA256_DIGEST_LENGTH];
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(user_key.data(), user_key.size(), hash.data());

    // Copier la partie nécessaire du hash dans la clé (si la clé est plus courte que 256 bits, on coupe)
    memcpy(key, hash.data(), key_len);
}


std::vector<unsigned char> CryptoUtils::decryptSym(std::vector<unsigned char> ciphertext,
                                                   std::vector<unsigned char> user_key) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int buf_len;
    const int key_len = 32;
    //unsigned char derived_key[key_len];
    std::vector<unsigned char> derived_key(key_len);

    // Load IV from end of ciphertext
    std::vector<unsigned char> iv(EVP_MAX_IV_LENGTH);
    iv.assign(ciphertext.end() - iv.size(), ciphertext.end());
    // Remove IV from ciphertext
    std::vector<unsigned char> ciphertext_without_iv(ciphertext.begin(), ciphertext.end() - iv.size());


    // Generate valid key from user key
    derive_key_from_user_key(std::move(user_key), derived_key.data(), key_len);

    if (!((ctx = EVP_CIPHER_CTX_new()))) {
        std::cerr << "Unable to create decryption context" << std::endl;
        handleOpenSSLErrors();
    }

    // Initialize cipher algo AES-256 CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, derived_key.data(), iv.data()) != 1) {
        std::cerr << "Unable to decrypt sym (EVP_DecryptInit_ex)" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLErrors();
    }

    // Allocate memory for ciphertext
    std::vector<unsigned char> plaintext_buf(ciphertext_without_iv.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    // Cipher
    if (EVP_DecryptUpdate(ctx, plaintext_buf.data(), &buf_len, ciphertext_without_iv.data(),
                          static_cast<int>(ciphertext_without_iv.size())) != 1) {
        std::cerr << "Unable to decrypt sym(EVP_DecryptUpdate)" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLErrors();
    }
    len = buf_len;

    // Finalise cipher
    if (EVP_DecryptFinal_ex(ctx, plaintext_buf.data() + buf_len, &buf_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        unsigned long errCode = ERR_get_error();
        if (errCode == 0x1C800064) {
            throw std::runtime_error("Wrong key or invalid data to decrypt");
        }
        std::cerr << "Unable to decrypt sym(EVP_DecryptFinal_ex)" << std::endl;
        handleOpenSSLErrors();
    }
    len += buf_len;
    plaintext_buf.resize(len);

    // Free ctx
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_buf;
}

std::vector<unsigned char> CryptoUtils::encryptSym(std::vector<unsigned char> plaintext,
                                                   std::vector<unsigned char> user_key) {
    // todo : manage max ciphered size (int)
    EVP_CIPHER_CTX *ctx;
    int buf_len;
    int len;
    const int key_len = 32;
    std::vector<unsigned char> derived_key(key_len);
    std::vector<unsigned char> iv(EVP_MAX_IV_LENGTH);
    // Generate random IV
    if (!RAND_bytes(iv.data(), EVP_MAX_IV_LENGTH)) {
        std::cerr << "Error generating IV" << std::endl;
        handleOpenSSLErrors();
    }

    // Generate key valid key from user key
    derive_key_from_user_key(std::move(user_key), derived_key.data(), key_len);


    if (!((ctx = EVP_CIPHER_CTX_new()))) throw std::runtime_error("Unable to create encryption context");

    // Initialize cipher algo AES-256 CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, derived_key.data(), iv.data()) != 1) {
        std::cerr << "Unable to encrypt sym(EVP_EncryptInit_ex)" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLErrors();
    }

    // Allocate memory for ciphertext
    std::vector<unsigned char> ciphertext_buf(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    // Cipher
    if (EVP_EncryptUpdate(ctx, ciphertext_buf.data(), &buf_len, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        std::cerr << "Unable to encrypt sym(EVP_EncryptUpdate)" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLErrors();
    }
    len = buf_len;

    // Finalise cipher
    if (EVP_EncryptFinal_ex(ctx, ciphertext_buf.data() + buf_len, &buf_len) != 1) {
        std::cerr << "Unable to encrypt sym(EVP_EncryptFinal_ex)" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLErrors();
    }
    len += buf_len;

    ciphertext_buf.resize(len);

    // Free ctx
    EVP_CIPHER_CTX_free(ctx);

    ciphertext_buf.insert(ciphertext_buf.end(), iv.begin(), iv.end());

    return ciphertext_buf;
}


///////////////////////////////// RSA
EVP_PKEY_ptr CryptoUtils::generate_rsa_key(int keylen) {
    //ENGINE *engine = ENGINE_by_id("dynamic");
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "Error creating RSA context\n" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLErrors();
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Error EVP_PKEY_keygen_init\n" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLErrors();
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keylen) <= 0) {
        //throw std::runtime_error("Can't set RSA key length");
        std::cerr << "Error setting keylen\n" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLErrors();
    }
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Error generating key\n" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        handleOpenSSLErrors();
    }

    EVP_PKEY_CTX_free(ctx);
    return EVP_PKEY_ptr(pkey);

    //EVP_CIPHER_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, ENGINE_new());
}

std::vector<unsigned char> CryptoUtils::rsa_decrypt(const std::vector<unsigned char> &cipherText, EVP_PKEY *priv_key) {
    std::vector<unsigned char> decryptedText;
    decryptedText.resize(EVP_PKEY_size(priv_key));

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) {
        std::cerr << "Unable to create decryption context for RSA" << std::endl;
        handleOpenSSLErrors();
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        std::cerr << "Unable to initialize decryption context for RSA" << std::endl;
        handleOpenSSLErrors();
    }

    size_t out_len = decryptedText.size();
    if (EVP_PKEY_decrypt(ctx, decryptedText.data(), &out_len, cipherText.data(), cipherText.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        std::cerr << "Decryption failed" << std::endl;
        handleOpenSSLErrors();
    }

    decryptedText.resize(out_len);
    EVP_PKEY_CTX_free(ctx);
    return decryptedText;
}

std::vector<unsigned char> CryptoUtils::rsa_encrypt(const std::vector<unsigned char> &plainText, EVP_PKEY *pub_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
    if (!ctx) {
        std::cerr << "Unable to create encryption context for RSA" << std::endl;
        handleOpenSSLErrors();
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        std::cerr << "Unable to initialize encryption context for RSA" << std::endl;
        handleOpenSSLErrors();
    }

    size_t out_len;
    if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, reinterpret_cast<const unsigned char *>(plainText.data()),
                         plainText.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        std::cerr << "Unable to determine encrypted length" << std::endl;
        handleOpenSSLErrors();
    }

    std::vector<unsigned char> encrypted(out_len);
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &out_len, reinterpret_cast<const unsigned char *>(plainText.data()),
                         plainText.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        std::cerr << "Encryption failed" << std::endl;
        handleOpenSSLErrors();
    }

    EVP_PKEY_CTX_free(ctx);
    return encrypted;
}


X509_ptr CryptoUtils::generate_certificate(EVP_PKEY *ca_key, X509 *ca_cert, EVP_PKEY *pub_key, const std::string &cn,
                                           const std::string &organisation, const std::string &country_code,
                                           int day_valid) {
    X509_ptr x509(X509_new());
    if (!x509) {
        std::cerr << "Unable to generate certificate" << std::endl;
        handleOpenSSLErrors();
    }
    X509_set_version(x509.get(), 3);
    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);
    // Define validity duration
    X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509.get()), day_valid * 60 * 60 * 24);

    // Associate pub key
    X509_set_pubkey(x509.get(), pub_key);

    // Configure issuer
    // If no root_cert, issuer is self
    if (ca_cert == nullptr) {
        const auto *issuer_str = (const unsigned char *) cn.data();
        X509_NAME *issuer_name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(issuer_name, "C", MBSTRING_ASC, (const unsigned char *) "XX", -1, -1, 0);
        X509_NAME_add_entry_by_txt(issuer_name, "O", MBSTRING_ASC, (const unsigned char *) "CastellumArchive", -1, -1,
                                   0);
        X509_NAME_add_entry_by_txt(issuer_name, "CN", MBSTRING_ASC, issuer_str, -1, -1, 0);
        X509_set_issuer_name(x509.get(), issuer_name);
    } else {
        X509_set_issuer_name(x509.get(), X509_get_issuer_name(ca_cert));
    }


    // Configure emitter name and subject
    X509_NAME *name = X509_get_subject_name(x509.get());
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *) "XX", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char *) "CastellumArchive", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *) cn.data(), -1, -1, 0);

    // If CA, set CA to true
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x509.get(), x509.get(), nullptr, nullptr, 0);
    std::string constraint_str = ca_cert == nullptr ? "CA:TRUE" : "CA:FALSE";
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, constraint_str.c_str());
    if (!ext) {
        std::cerr << "Unable to create certificate extension" << std::endl;
        handleOpenSSLErrors();
    }
    if (X509_add_ext(x509.get(), ext, -1) != 1) {
        std::cerr << "Unable to add certificate extension" << std::endl;
        handleOpenSSLErrors();
    }

    // Define certificate emitter (sign)
    if (!X509_sign(x509.get(), ca_key, EVP_sha256())) {
        std::cerr << "Unable to sign certificate" << std::endl;
        handleOpenSSLErrors();
    }
    return x509;
}

std::vector<unsigned char> CryptoUtils::export_pub_key(const EVP_PKEY *key) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_PUBKEY(bio.get(), key);
    char *pem_data;
    long pem_size = BIO_get_mem_data(bio.get(), &pem_data);
    return std::vector<unsigned char>(pem_data, pem_data+pem_size);

}

std::vector<unsigned char> CryptoUtils::export_priv_key(const EVP_PKEY *pub_key, const std::string &password) {
    OSSL_ENCODER_CTX *ectx;
    const char *format = "PEM";
    const char *structure =	"PrivateKeyInfo"; /* PKCS#8 structure */

    ectx = OSSL_ENCODER_CTX_new_for_pkey(pub_key,
                         OSSL_KEYMGMT_SELECT_KEYPAIR,
                         format, structure,
                         nullptr);
    if (ectx == nullptr) {
        std::cerr << "Unable to create context for public key loading" << std::endl;
        handleOpenSSLErrors();
    }
    if(!password.empty()) {
        OSSL_ENCODER_CTX_set_passphrase(ectx, reinterpret_cast<const unsigned char *>(password.c_str()), password.length());
        OSSL_ENCODER_CTX_set_cipher(ectx, "AES-256-CBC", nullptr);
    }

    const BioPtr bio(BIO_new(BIO_s_mem()));

    if (!OSSL_ENCODER_to_bio(ectx, bio.get())) {
        std::cout << "Failed to export public key" << std::endl;
        handleOpenSSLErrors();
    }
    OSSL_ENCODER_CTX_free(ectx);
    return get_bio_to_pem(bio.get());
}

EVP_PKEY_ptr CryptoUtils::load_priv_key(const std::vector<unsigned char> &priv_key_pem, const std::string& password) {
    /*BioPtr bio(BIO_new(BIO_s_mem()));
    BIO_write(bio.get(), priv_key_pem.data(), static_cast<int>(priv_key_pem.size()));
    EVP_PKEY_ptr priv_key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    if(!priv_key) {
        std::cerr << "Unable to load private key" << std::endl;
        handleOpenSSLErrors();
    }
    return priv_key;*/
    BioPtr bio(BIO_new(BIO_s_mem()));
    BIO_write(bio.get(), priv_key_pem.data(), static_cast<int>(priv_key_pem.size()));

    EVP_PKEY* priv_key;

    OSSL_DECODER_CTX* dctx = OSSL_DECODER_CTX_new_for_pkey(&priv_key, "PEM", nullptr, "RSA",
        OSSL_KEYMGMT_SELECT_KEYPAIR, nullptr, nullptr);
    if(dctx == nullptr) {
        std::cerr << "Unable to create decoder for public key" << std::endl;
        handleOpenSSLErrors();
    }
    if(!password.empty()) {
        OSSL_DECODER_CTX_set_passphrase(dctx, reinterpret_cast<const unsigned char *>(password.c_str()), password.length());
    }
    if(OSSL_DECODER_from_bio(dctx, bio.get()) != 1) {
        std::cerr << "Unable to load public key from bio" << std::endl;
        OSSL_DECODER_CTX_free(dctx);
        handleOpenSSLErrors();
    }

    OSSL_DECODER_CTX_free(dctx);


    return EVP_PKEY_ptr(priv_key);
}

EVP_PKEY_ptr CryptoUtils::load_pub_key(std::vector<unsigned char> pub_key_pem) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    BIO_write(bio.get(), pub_key_pem.data(), static_cast<int>(pub_key_pem.size()));

    EVP_PKEY* pub_key;

    OSSL_DECODER_CTX* dctx = OSSL_DECODER_CTX_new_for_pkey(&pub_key, "PEM", nullptr, "RSA",
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY, nullptr, nullptr);
    if(dctx == nullptr) {
        std::cerr << "Unable to create decoder for public key" << std::endl;
        OSSL_DECODER_CTX_free(dctx);
        handleOpenSSLErrors();
    }
    if(OSSL_DECODER_from_bio(dctx, bio.get()) != 1) {
        std::cerr << "Unable to load public key" << std::endl;
        OSSL_DECODER_CTX_free(dctx);
        handleOpenSSLErrors();
    }

    OSSL_DECODER_CTX_free(dctx);


    return EVP_PKEY_ptr(pub_key);
}

BioPtr CryptoUtils::certificate_to_bio(X509 *cert) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        std::cerr << "Unable to allocate BIO" << std::endl;
        handleOpenSSLErrors();
    }
    if (!PEM_write_bio_X509(bio.get(), cert)) {
        std::cerr << "Unable to write certificate to BIO" << std::endl;
        handleOpenSSLErrors();
    }
    return bio;
}

std::vector<unsigned char> CryptoUtils::get_bio_to_pem(BIO *bio) {
    char *pem_data;
    long pem_size = BIO_get_mem_data(bio, &pem_data);
    return std::vector<unsigned char>(pem_data, pem_data + pem_size);
}

bool CryptoUtils::check_certificate_validity(X509 *cert, X509 *authority) {
    X509Store_ptr store(X509_STORE_new());
    if (!store) {
        std::cerr << "Unable to create store" << std::endl;
        handleOpenSSLErrors();
    }

    X509_STORE_add_cert(store.get(), authority);

    X509StoreCtx_ptr ctx(X509_STORE_CTX_new());
    if (!ctx) {
        std::cerr << "Unable to create store context" << std::endl;
        handleOpenSSLErrors();
    }

    if (X509_STORE_CTX_init(ctx.get(), store.get(), cert, nullptr) != 1) {
        std::cerr << "Unable to initialize store context" << std::endl;
        handleOpenSSLErrors();
    }

    if (X509_verify_cert(ctx.get()) != 1) {
        std::cerr << "Unable to verify certificate" << std::endl;
        handleOpenSSLErrors();
    }
    return true;
}

X509_ptr CryptoUtils::load_certificate(std::vector<unsigned char> pem_cert) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        std::cerr << "Unable to load certificate" << std::endl;
        handleOpenSSLErrors();
    }
    if (BIO_write(bio.get(), pem_cert.data(), pem_cert.size()) <= 0) {
        std::cerr << "Unable to write to BIO" << std::endl;
        handleOpenSSLErrors();
    }

    X509_ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!cert) {
        std::cerr << "Unable to load certificate" << std::endl;
        handleOpenSSLErrors();
    }
    return cert;
}

std::vector<unsigned char> CryptoUtils::signData(EVP_PKEY *priv_key, std::vector<unsigned char> data) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        std::cerr << "Unable to create MD context" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        handleOpenSSLErrors();
    }
    if (EVP_SignInit(md_ctx, EVP_sha256()) <= 0) {
        std::cerr << "Unable to initialize MD context" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        handleOpenSSLErrors();
    }

    // Add data to signature
    if (EVP_SignUpdate(md_ctx, data.data(), data.size()) <= 0) {
        std::cerr << "Unable to add data to MD context" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        handleOpenSSLErrors();
    }

    unsigned int sig_len = 0;
    std::vector<unsigned char> signature(EVP_PKEY_size(priv_key));
    // Sign digest with priv key
    if (EVP_SignFinal(md_ctx, signature.data(), &sig_len, priv_key) <= 0) {
        std::cerr << "Unable to sign MD context" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        handleOpenSSLErrors();
    }

    signature.resize(sig_len);
    EVP_MD_CTX_free(md_ctx);

    return signature;
}

bool CryptoUtils::checkSignature(std::vector<unsigned char> data, std::vector<unsigned char> signature, X509 *certificate) {
    EVP_PKEY_ptr public_key(X509_get_pubkey(certificate));
    if (!public_key) {
        std::cerr << "Unable to get public key" << std::endl;
        handleOpenSSLErrors();
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        std::cerr << "Unable to create MD ctx" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        handleOpenSSLErrors();
    }

    if (EVP_VerifyInit(md_ctx, EVP_sha256()) <= 0) {
        std::cerr << "Unable to initialize MD ctx" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        handleOpenSSLErrors();
    }

    if (EVP_VerifyUpdate(md_ctx, data.data(), data.size()) <= 0) {
        std::cerr << "Unable to verify MD ctx" << std::endl;
        EVP_MD_CTX_free(md_ctx);
        handleOpenSSLErrors();
    }

    int result = EVP_VerifyFinal(md_ctx, signature.data(), signature.size(), public_key.get());
    ERR_clear_error();

    EVP_MD_CTX_free(md_ctx);
    return result == 1;
}
