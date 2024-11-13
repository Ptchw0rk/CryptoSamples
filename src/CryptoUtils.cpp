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
#include <cstring>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <variant>
#include <vector>

void CryptoUtils::handleOpenSSLErrors() {
	unsigned long errCode;
	while ((errCode = ERR_get_error())) {
		char *err = ERR_error_string(errCode, nullptr);
		std::cerr << "Error: " << err << std::endl;
	}
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
void CryptoUtils::derive_key_from_user_key(const std::string& user_key, unsigned char* key, int key_len) {
	// Utiliser SHA-256 pour générer une clé de longueur fixe
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256((unsigned char*)user_key.c_str(), user_key.size(), hash);

	// Copier la partie nécessaire du hash dans la clé (si la clé est plus courte que 256 bits, on coupe)
	memcpy(key, hash, key_len);
}



std::string CryptoUtils::decryptSym(const std::string& ciphertext, const std::string& user_key) {
	EVP_CIPHER_CTX* ctx;
	int plaintext_len;
	int len;
	const int key_len = 32;
	unsigned char key[key_len];

	unsigned char iv[EVP_MAX_IV_LENGTH];
	if(!RAND_bytes(iv, EVP_MAX_IV_LENGTH)) {
		throw std::runtime_error("Error generating IV");
	}

	// Generate key valid key from user key
	derive_key_from_user_key(user_key, key, key_len);

	if (!((ctx = EVP_CIPHER_CTX_new()))) throw std::runtime_error("Unable to create decryption context");

	// Initialize cipher algo AES-256 CBC
	if(!true != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) throw std::runtime_error("Unable to decrypt sym");

	// Allocate memory for ciphertext
	unsigned char plaintext_buf[ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc())];

	// Cipher
	if(1 != EVP_DecryptUpdate(ctx, plaintext_buf, &len, (unsigned char*)ciphertext.c_str(), (int)ciphertext.size())) throw std::runtime_error("Unable to encrypt sym");
	plaintext_len = len;

	// Finalise cipher
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext_buf, &plaintext_len)) throw std::runtime_error("Unable to decrypt sym");
	plaintext_len += len;

	// Copy cipher result in new string
	std::string plaintext = std::string(reinterpret_cast<char*>(plaintext_buf), plaintext_len);


	// Free ctx
	EVP_CIPHER_CTX_free(ctx);

	return plaintext;
}

std::string CryptoUtils::encryptSym(const std::string& plaintext, const std::string& user_key) {
	EVP_CIPHER_CTX* ctx;
	int ciphertext_len;
	int len;
	const int key_len = 32;
	unsigned char key[key_len];

	unsigned char iv[EVP_MAX_IV_LENGTH];
	if(!RAND_bytes(iv, EVP_MAX_IV_LENGTH)) {
		throw std::runtime_error("Error generating IV");
	}

	// Generate key valid key from user key
	derive_key_from_user_key(user_key, key, key_len);

	if (!((ctx = EVP_CIPHER_CTX_new()))) throw std::runtime_error("Unable to create encryption context");

	// Initialize cipher algo AES-256 CBC
	if(!true != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) throw std::runtime_error("Unable to encrypt vault");

	// Allocate memory for ciphertext
	unsigned char ciphertext_buf[plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc())];

	// Cipher
	if(1 != EVP_EncryptUpdate(ctx, ciphertext_buf, &len, (unsigned char*)plaintext.c_str(),
							   static_cast<int>(plaintext.size()))) throw std::runtime_error("Unable to encrypt vault");
	ciphertext_len = len;

	// Finalise cipher
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext_buf, &ciphertext_len)) throw std::runtime_error("Unable to encrypt vault");
	ciphertext_len += len;

	// Copy cipher result in new string
	std::string ciphertext = std::string(reinterpret_cast<char*>(ciphertext_buf), ciphertext_len);

	// Free ctx
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext;
}



///////////////////////////////// RSA
EVP_PKEY_ptr CryptoUtils::generate_rsa_key(int keylen) {
	//ENGINE *engine = ENGINE_by_id("dynamic");
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	if(!ctx) {
		std::printf("Error creating RSA context\n");
		handleOpenSSLErrors();
	}
	if(EVP_PKEY_keygen_init(ctx) <= 0) {
		std::printf("Error EVP_PKEY_keygen_init\n");
		handleOpenSSLErrors();
	}
	if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keylen) <= 0) {
		//throw std::runtime_error("Can't set RSA key length");
		std::printf("Error setting keylen\n");
		handleOpenSSLErrors();
	}
	EVP_PKEY* pkey = nullptr;
	if(EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		std::printf("Error generating key\n");
		//throw std::runtime_error("Can't generate RSA key");
		handleOpenSSLErrors();
	}


	EVP_PKEY_CTX_free(ctx);
	return EVP_PKEY_ptr(pkey);

	//EVP_CIPHER_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, ENGINE_new());

}

std::vector<unsigned char> CryptoUtils::rsa_decrypt(const std::vector<unsigned char>& cipherText, EVP_PKEY* pkey) {
	std::vector<unsigned char> decryptedText;
	decryptedText.resize(EVP_PKEY_size(pkey));

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
	if (!ctx) {
		throw std::runtime_error("Unable to create decryption context for RSA");
	}
	if (EVP_PKEY_decrypt_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Unable to initialize decryption context for RSA");
	}

	size_t out_len = decryptedText.size();
	if (EVP_PKEY_decrypt(ctx, decryptedText.data(), &out_len, cipherText.data(), cipherText.size()) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Decryption failed");
	}

	decryptedText.resize(out_len);
	EVP_PKEY_CTX_free(ctx);
	return decryptedText;
}

std::vector<unsigned char> CryptoUtils::rsa_encrypt(const std::vector<char> plainText, EVP_PKEY* pkey) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
	if (!ctx) {
		throw std::runtime_error("Unable to create encryption context for RSA");
	}
	if (EVP_PKEY_encrypt_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Unable to initialize encryption context for RSA");
	}

	size_t out_len;
	if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, reinterpret_cast<const unsigned char*>(plainText.data()), plainText.size()) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Unable to determine encrypted length");
	}

	std::vector<unsigned char> encrypted(out_len);
	if (EVP_PKEY_encrypt(ctx, encrypted.data(), &out_len, reinterpret_cast<const unsigned char*>(plainText.data()), plainText.size()) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Encryption failed");
	}

	EVP_PKEY_CTX_free(ctx);
	return encrypted;
}


std::string CryptoUtils::get_pub_key(EVP_PKEY *priv_key) {
	BioPtr bio(BIO_new(BIO_s_mem()));
	PEM_write_bio_PUBKEY(bio.get(), priv_key);
	char* pem_data;
	long pem_size = BIO_get_mem_data(bio.get(), &pem_data);
	return std::string(pem_data, pem_size);
}

// https://www.talm.ai/how-to-access-the-raw-public-private-tuple-and-params-inside-openssls-evp_pkey-structure/