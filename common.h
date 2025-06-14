#ifndef COMMON_H
#define COMMON_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <map>
#include <wordexp.h>



// General Utilities
void init_openssl();
void cleanup_openssl();
void error_exit(const std::string& msg);
void print_openssl_errors(const std::string& msg);
std::string get_server_address_string(const sockaddr_in* addr);


// Key Management & Cryptography
EVP_PKEY* generate_ecdsa_key();
EVP_PKEY* load_pkey_pem(const std::string& filepath, bool is_public);
bool save_pkey_pem(EVP_PKEY* pkey, const std::string& filepath, bool is_private);
std::vector<unsigned char> get_public_key_der(EVP_PKEY* pkey);
EVP_PKEY* create_pkey_from_public_der(const std::vector<unsigned char>& der_bytes);
std::string calculate_public_key_fingerprint(EVP_PKEY* public_key);


std::string bytes_to_hex(const std::vector<unsigned char>& bytes); //
bool send_message(int sock, const std::vector<unsigned char>& data); //
std::vector<unsigned char> receive_message(int sock); //
void init_openssl(); //
void cleanup_openssl(); //
void error_exit(const std::string& msg); //
void print_openssl_errors(const std::string& msg); //
std::string get_server_address_string(const sockaddr_in* addr); //



// ECDH & Session Key Derivation
EVP_PKEY* generate_ecdh_key();
std::vector<unsigned char> derive_shared_secret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key);
std::vector<unsigned char> calculate_sha256(const std::vector<unsigned char>& data);



const EVP_CIPHER* get_aes_cipher();
// AES-GCM Encryption Constants
const int AES_KEY_SIZE = 32;
const int AES_GCM_IV_SIZE = 12;
const int AES_GCM_TAG_SIZE = 16;


std::vector<unsigned char> perform_encryption(const std::vector<unsigned char>& plaintext,
                                              const unsigned char* key, const unsigned char* iv,
                                              std::vector<unsigned char>& tag);

bool perform_decryption(const std::vector<unsigned char>& ciphertext,
                        const std::vector<unsigned char>& tag,
                        const unsigned char* key, const unsigned char* iv,
                        std::vector<unsigned char>& plaintext);



std::vector<unsigned char> calculate_sha256(const std::vector<unsigned char>& data);

std::string bytes_to_hex(const std::vector<unsigned char>& bytes);

std::string calculate_public_key_fingerprint(EVP_PKEY* public_key);


unsigned char* perform_server_handshake(int client_sock, const sockaddr_in* client_addr, 
                            EVP_PKEY* server_static_key, EVP_PKEY*& client_ephemeral_pubkey);
unsigned char* perform_client_handshake(int sock, const std::string& server_address,
                            EVP_PKEY*& server_static_pubkey);


bool send_message(int sock, const std::vector<unsigned char>& data);
std::vector<unsigned char> receive_message(int sock);


bool send_encrypted_message(int sock, const std::vector<unsigned char>& plaintext,
                            const unsigned char* key); 
std::vector<unsigned char> receive_encrypted_message(int sock, const unsigned char* key);


const std::string KNOWN_HOSTS_FILE = "known_hosts.txt";
std::map<std::string, std::string> read_known_hosts();
bool write_known_hosts(const std::map<std::string, std::string>& known_hosts);
std::string get_server_address_string(const sockaddr_in* addr);


void error_exit(const std::string& msg);
void print_openssl_errors(const std::string& msg);

std::string expand_path(const std::string& path);

#endif