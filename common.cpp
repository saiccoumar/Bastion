#include "common.h"

void init_openssl() {
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
}

void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
    
}

EVP_PKEY* generate_ecdsa_key() {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        print_openssl_errors("EVP_PKEY_CTX_new_id failed");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        print_openssl_errors("EVP_PKEY_keygen_init failed");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
         print_openssl_errors("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed");
         EVP_PKEY_CTX_free(ctx);
         return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        print_openssl_errors("EVP_PKEY_keygen failed");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

EVP_PKEY* load_pkey_pem(const std::string& filepath, bool is_public) {
    FILE* fp = fopen(filepath.c_str(), "r");
    if (!fp) {
        std::cerr << "[Error] Could not open key file: " << filepath << std::endl;
        return NULL;
    }

    EVP_PKEY* pkey = NULL;
    if (is_public) {
        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    } else {
        pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    }

    fclose(fp);

    if (!pkey) {
        print_openssl_errors("Failed to read PEM key");
    }
    return pkey;
}

bool save_pkey_pem(EVP_PKEY* pkey, const std::string& filepath, bool is_public) {
    FILE* fp = fopen(filepath.c_str(), "w");
    if (!fp) {
        std::cerr << "[Error] Could not create key file: " << filepath << std::endl;
        return false;
    }

    bool success = false;
    if (is_public) {
        if (PEM_write_PUBKEY(fp, pkey)) success = true;
    } else {
        if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) success = true;
    }

    fclose(fp);

    if (!success) {
        print_openssl_errors("Failed to write PEM key");
    }
    return success;
}

std::vector<unsigned char> get_public_key_der(EVP_PKEY* pkey) {
    std::vector<unsigned char> der_bytes;
    int der_len = i2d_PUBKEY(pkey, NULL);
    if (der_len <= 0) {
        print_openssl_errors("i2d_PUBKEY failed (length calculation)");
        return der_bytes; 
    }

    der_bytes.resize(der_len);
    unsigned char* p = der_bytes.data();
    if (i2d_PUBKEY(pkey, &p) != der_len) {
        print_openssl_errors("i2d_PUBKEY failed");
        der_bytes.clear(); 
    }
    return der_bytes;
}

EVP_PKEY* create_pkey_from_public_der(const std::vector<unsigned char>& der_bytes) {
    if (der_bytes.empty()) return NULL;
    const unsigned char* p = der_bytes.data();
    return d2i_PUBKEY(NULL, &p, der_bytes.size());
}


EVP_PKEY* generate_ecdh_key() {
     EVP_PKEY* pkey = NULL;
     EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
     if (!ctx) {
         print_openssl_errors("EVP_PKEY_CTX_new_id for ECDH failed");
         return NULL;
     }

     if (EVP_PKEY_keygen_init(ctx) <= 0) {
         print_openssl_errors("EVP_PKEY_keygen_init for ECDH failed");
         EVP_PKEY_CTX_free(ctx);
         return NULL;
     }

     
     if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
         print_openssl_errors("EVP_PKEY_CTX_set_ec_paramgen_curve_nid for ECDH failed");
         EVP_PKEY_CTX_free(ctx);
         return NULL;
     }

     if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
         print_openssl_errors("EVP_PKEY_keygen for ECDH failed");
         EVP_PKEY_CTX_free(ctx);
         return NULL;
     }

     EVP_PKEY_CTX_free(ctx);
     return pkey;
}

std::vector<unsigned char> derive_shared_secret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) {
    std::vector<unsigned char> shared_secret;
    EVP_PKEY_CTX* ctx = NULL;

    ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) {
         print_openssl_errors("EVP_PKEY_CTX_new for ECDH derive failed");
         return shared_secret;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        print_openssl_errors("EVP_PKEY_derive_init for ECDH failed");
        EVP_PKEY_CTX_free(ctx);
        return shared_secret;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_public_key) <= 0) {
        print_openssl_errors("EVP_PKEY_derive_set_peer for ECDH failed");
        EVP_PKEY_CTX_free(ctx);
        return shared_secret;
    }

    size_t secret_len;
    
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
        print_openssl_errors("EVP_PKEY_derive (get len) for ECDH failed");
        EVP_PKEY_CTX_free(ctx);
        return shared_secret;
    }

    shared_secret.resize(secret_len);
    
    if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) {
        print_openssl_errors("EVP_PKEY_derive for ECDH failed");
        shared_secret.clear(); 
    }

    EVP_PKEY_CTX_free(ctx);
    return shared_secret;
}

const EVP_CIPHER* get_aes_cipher() {
    return EVP_aes_256_gcm();
}

std::vector<unsigned char> perform_encryption(const std::vector<unsigned char>& plaintext,
                                              const unsigned char* key, const unsigned char* iv,
                                              std::vector<unsigned char>& tag) {
    std::vector<unsigned char> ciphertext;
    tag.resize(AES_GCM_TAG_SIZE);

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        print_openssl_errors("EVP_CIPHER_CTX_new failed");
        return ciphertext; 
    }

    if (1 != EVP_EncryptInit_ex(ctx, get_aes_cipher(), NULL, key, iv)) {
        print_openssl_errors("EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return ciphertext; 
    }

    ciphertext.resize(plaintext.size()); 

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        print_openssl_errors("EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return ciphertext; 
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &len)) {
         print_openssl_errors("EVP_EncryptFinal_ex failed");
         EVP_CIPHER_CTX_free(ctx);
         return ciphertext; 
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag.data())) {
        print_openssl_errors("EVP_CIPHER_CTX_ctrl (GET_TAG) failed");
        EVP_CIPHER_CTX_free(ctx);
        ciphertext.clear(); tag.clear(); 
        return ciphertext;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

bool perform_decryption(const std::vector<unsigned char>& ciphertext,
                        const std::vector<unsigned char>& tag,
                        const unsigned char* key, const unsigned char* iv,
                        std::vector<unsigned char>& plaintext) {
    plaintext.clear();

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        print_openssl_errors("EVP_CIPHER_CTX_new failed");
        return false;
    }

    if (1 != EVP_DecryptInit_ex(ctx, get_aes_cipher(), NULL, key, iv)) {
         print_openssl_errors("EVP_DecryptInit_ex failed");
         EVP_CIPHER_CTX_free(ctx);
         return false;
    }

    plaintext.resize(ciphertext.size()); 

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
         print_openssl_errors("EVP_DecryptUpdate failed");
         EVP_CIPHER_CTX_free(ctx);
         return false;
    }
    plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void*)tag.data())) {
        print_openssl_errors("EVP_CIPHER_CTX_ctrl (SET_TAG) failed");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return true; 
    } else {
        print_openssl_errors("EVP_DecryptFinal_ex (Tag verification failed)");
        plaintext.clear(); 
        return false; 
    }
}

unsigned char* perform_client_handshake(int sock, const std::string& server_address_str,
                                        EVP_PKEY*& server_static_pubkey_out) {
    print_openssl_errors("Start client handshake");

    // Receive server's static public key
    std::vector<unsigned char> server_static_pub_der = receive_message(sock);
    if (server_static_pub_der.empty()) {
        std::cerr << "[Client] Failed to receive server static public key." << std::endl;
        return nullptr;
    }
    server_static_pubkey_out = create_pkey_from_public_der(server_static_pub_der);
    if (!server_static_pubkey_out) {
        std::cerr << "[Client] Failed to create EVP_PKEY from server static key DER." << std::endl;
        return nullptr;
    }
    std::cout << "[Client] Received server static public key." << std::endl;

    // Receive server's ephemeral public key
    std::vector<unsigned char> server_ephemeral_pub_der = receive_message(sock);
    if (server_ephemeral_pub_der.empty()) {
        std::cerr << "[Client] Failed to receive server ephemeral public key." << std::endl;
        return nullptr;
    }
    EVP_PKEY* server_ephemeral_pubkey = create_pkey_from_public_der(server_ephemeral_pub_der);
    if (!server_ephemeral_pubkey) {
        std::cerr << "[Client] Failed to create EVP_PKEY from server ephemeral key DER." << std::endl;
        return nullptr;
    }
    std::cout << "[Client] Received server ephemeral public key." << std::endl;

    // Generate client's ephemeral key for ECDH
    EVP_PKEY* client_ephemeral_key = generate_ecdh_key();
    if (!client_ephemeral_key) {
        std::cerr << "[Client] Failed to generate ephemeral key." << std::endl;
        EVP_PKEY_free(server_ephemeral_pubkey);
        return nullptr;
    }

    // Send client's ephemeral public key to the server
    std::vector<unsigned char> client_ephemeral_pub_der = get_public_key_der(client_ephemeral_key);
    if (!send_message(sock, client_ephemeral_pub_der)) {
        std::cerr << "[Client] Failed to send client ephemeral public key." << std::endl;
        EVP_PKEY_free(server_ephemeral_pubkey);
        EVP_PKEY_free(client_ephemeral_key);
        return nullptr;
    }
    std::cout << "[Client] Sent client ephemeral public key." << std::endl;

    // Derive shared secret
    std::vector<unsigned char> shared_secret = derive_shared_secret(client_ephemeral_key, server_ephemeral_pubkey);
    EVP_PKEY_free(client_ephemeral_key);   // No longer needed
    EVP_PKEY_free(server_ephemeral_pubkey); // No longer needed

    if (shared_secret.empty()) {
        std::cerr << "[Client] Failed to derive shared secret." << std::endl;
        return nullptr;
    }
    std::cout << "[Client] Derived shared secret (size: " << shared_secret.size() << ")." << std::endl;

    // Hash the secret to create the session key
    std::vector<unsigned char> hashed_secret = calculate_sha256(shared_secret);
    if (hashed_secret.size() < AES_KEY_SIZE) {
        std::cerr << "[Client] Hashed secret is too short for an AES key." << std::endl;
        return nullptr;
    }

    unsigned char* session_key = new unsigned char[AES_KEY_SIZE];
    memcpy(session_key, hashed_secret.data(), AES_KEY_SIZE);
    std::cout << "[Client] Derived session key." << std::endl;

    return session_key;
}

unsigned char* perform_server_handshake(int client_sock, const sockaddr_in* client_addr, 
                            EVP_PKEY* server_static_key, EVP_PKEY*& client_ephemeral_pubkey) {
    print_openssl_errors("Start server handshake");

    EVP_PKEY* server_ephemeral_key = generate_ecdh_key();
    if (!server_ephemeral_key) {
        std::cerr << "[Server] Failed to generate ephemeral key." << std::endl;
        return nullptr;
    }

    // Now using server_static_key parameter instead of global variable
    std::vector<unsigned char> static_pub_der = get_public_key_der(server_static_key);
    std::vector<unsigned char> ephemeral_pub_der = get_public_key_der(server_ephemeral_key);

    if (static_pub_der.empty() || ephemeral_pub_der.empty()) {
        EVP_PKEY_free(server_ephemeral_key);
        return nullptr;
    }

    
    if (!send_message(client_sock, static_pub_der)) {
        std::cerr << "[Server] Failed to send static public key." << std::endl;
        EVP_PKEY_free(server_ephemeral_key);
        return nullptr;
    }

    
    if (!send_message(client_sock, ephemeral_pub_der)) {
        std::cerr << "[Server] Failed to send ephemeral public key." << std::endl;
        EVP_PKEY_free(server_ephemeral_key);
        return nullptr;
    }
     std::cout << "[Server] Sent static and ephemeral public keys." << std::endl;


    
    std::vector<unsigned char> client_ephemeral_pub_der = receive_message(client_sock);
    if (client_ephemeral_pub_der.empty()) {
        std::cerr << "[Server] Failed to receive client ephemeral public key." << std::endl;
        EVP_PKEY_free(server_ephemeral_key);
        return nullptr;
    }
    std::cout << "[Server] Received client ephemeral public key." << std::endl;


    
    client_ephemeral_pubkey = create_pkey_from_public_der(client_ephemeral_pub_der);
    if (!client_ephemeral_pubkey) {
        std::cerr << "[Server] Failed to create EVP_PKEY from client public key DER." << std::endl;
        EVP_PKEY_free(server_ephemeral_key);
        return nullptr;
    }

    
    std::vector<unsigned char> shared_secret = derive_shared_secret(server_ephemeral_key, client_ephemeral_pubkey);
    EVP_PKEY_free(server_ephemeral_key); 

    if (shared_secret.empty()) {
        std::cerr << "[Server] Failed to derive shared secret." << std::endl;
        EVP_PKEY_free(client_ephemeral_pubkey); 
        client_ephemeral_pubkey = NULL;
        return nullptr;
    }
     std::cout << "[Server] Derived shared secret (size: " << shared_secret.size() << ")." << std::endl;


    
    
    std::vector<unsigned char> hashed_secret = calculate_sha256(shared_secret);
    if (hashed_secret.size() < AES_KEY_SIZE) {
        std::cerr << "[Server] Hashed shared secret is too short for AES key." << std::endl;
        EVP_PKEY_free(client_ephemeral_pubkey);
        client_ephemeral_pubkey = NULL;
        return nullptr;
    }

    unsigned char* session_key = new unsigned char[AES_KEY_SIZE];
    memcpy(session_key, hashed_secret.data(), AES_KEY_SIZE);
    std::cout << "[Server] Derived session key." << std::endl;

    return session_key;
}


std::vector<unsigned char> calculate_sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

std::string calculate_public_key_fingerprint(EVP_PKEY* public_key) {
    std::vector<unsigned char> der = get_public_key_der(public_key);
    if (der.empty()) return "";
    std::vector<unsigned char> hash = calculate_sha256(der);
    return bytes_to_hex(hash);
}


bool send_all(int sock, const unsigned char* buf, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = write(sock, buf + total_sent, len - total_sent);
        if (sent <= 0) {
            if (sent < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue; 
            }
            std::cerr << "[Socket Error] Failed to send data: " << strerror(errno) << std::endl;
            return false;
        }
        total_sent += sent;
    }
    return true;
}

std::vector<unsigned char> receive_all(int sock, size_t len) {
    std::vector<unsigned char> data(len);
    size_t total_received = 0;
    while (total_received < len) {
        ssize_t received = read(sock, data.data() + total_received, len - total_received);
        if (received <= 0) {
             if (received < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue; 
            }
            if (received == 0) {
                 std::cerr << "[Socket Error] Connection closed by peer while receiving data." << std::endl;
            } else {
                std::cerr << "[Socket Error] Failed to receive data: " << strerror(errno) << std::endl;
            }
            return {}; 
        }
        total_received += received;
    }
    return data;
}



bool send_message(int sock, const std::vector<unsigned char>& data) {
    uint32_t len = data.size();
    uint32_t network_len = htonl(len);

    if (!send_all(sock, (const unsigned char*)&network_len, sizeof(network_len))) return false;
    if (len > 0) {
        if (!send_all(sock, data.data(), len)) return false;
    }
    return true;
}


std::vector<unsigned char> receive_message(int sock) {
    uint32_t network_len;
    auto len_buffer = receive_all(sock, sizeof(network_len));
    if (len_buffer.empty()) return {}; 
    memcpy(&network_len, len_buffer.data(), sizeof(network_len));
    uint32_t len = ntohl(network_len);

    if (len == 0) {
        return {}; 
    }

    return receive_all(sock, len);
}


bool send_encrypted_message(int sock, const std::vector<unsigned char>& plaintext,
                            const unsigned char* key) {

    
    std::vector<unsigned char> iv(AES_GCM_IV_SIZE);
    if (RAND_bytes(iv.data(), AES_GCM_IV_SIZE) <= 0) {
        print_openssl_errors("RAND_bytes for IV failed");
        return false;
    }

    std::vector<unsigned char> tag;
    std::vector<unsigned char> ciphertext = perform_encryption(plaintext, key, iv.data(), tag);
    if (ciphertext.empty()) return false; 

    
    uint32_t iv_len = iv.size();
    uint32_t ciphertext_len = ciphertext.size();

    
    uint32_t network_iv_len = htonl(iv_len);
    if (!send_all(sock, (const unsigned char*)&network_iv_len, sizeof(network_iv_len))) return false;

    
    if (!send_all(sock, iv.data(), iv_len)) return false;

    
    uint32_t network_ciphertext_len = htonl(ciphertext_len);
    if (!send_all(sock, (const unsigned char*)&network_ciphertext_len, sizeof(network_ciphertext_len))) return false;

    
    if (!send_all(sock, ciphertext.data(), ciphertext_len)) return false;

    
    if (!send_all(sock, tag.data(), tag.size())) return false;

    return true;
}


std::vector<unsigned char> receive_encrypted_message(int sock, const unsigned char* key) {
    std::vector<unsigned char> plaintext;

    // Read IV length
    uint32_t network_iv_len;
    auto iv_len_buffer = receive_all(sock, sizeof(network_iv_len));
    if (iv_len_buffer.empty()) return {};
    memcpy(&network_iv_len, iv_len_buffer.data(), sizeof(network_iv_len));
    uint32_t iv_len = ntohl(network_iv_len);

    if (iv_len != AES_GCM_IV_SIZE) {
        std::cerr << "[Error] Received unexpected IV length: " << iv_len << std::endl;
        return {};
    }

    // Read IV
    std::vector<unsigned char> iv = receive_all(sock, iv_len);
    if (iv.empty()) return {};

    // Read ciphertext length
    uint32_t network_ciphertext_len;
    auto ciphertext_len_buffer = receive_all(sock, sizeof(network_ciphertext_len));
    if (ciphertext_len_buffer.empty()) return {};
    memcpy(&network_ciphertext_len, ciphertext_len_buffer.data(), sizeof(network_ciphertext_len));
    uint32_t ciphertext_len = ntohl(network_ciphertext_len);

    // Read ciphertext
    std::vector<unsigned char> ciphertext = receive_all(sock, ciphertext_len);
    if (ciphertext.empty()) return {};

    // Read tag
    std::vector<unsigned char> tag = receive_all(sock, AES_GCM_TAG_SIZE);
    if (tag.empty()) return {};

    // Perform decryption
    if (!perform_decryption(ciphertext, tag, key, iv.data(), plaintext)) {
        std::cerr << "[Error] Decryption or tag verification failed." << std::endl;
        return {};
    }

    return plaintext;
}


std::map<std::string, std::string> read_known_hosts() {
    std::map<std::string, std::string> known_hosts;
    std::ifstream infile(KNOWN_HOSTS_FILE);
    std::string line;
    while (std::getline(infile, line)) {
        std::stringstream ss(line);
        std::string address;
        std::string fingerprint;
        if (std::getline(ss, address, ' ') && std::getline(ss, fingerprint)) {
            known_hosts[address] = fingerprint;
        }
    }
    return known_hosts;
}

bool write_known_hosts(const std::map<std::string, std::string>& known_hosts) {
    std::ofstream outfile(KNOWN_HOSTS_FILE);
    if (!outfile) {
        std::cerr << "[Error] Could not write to known_hosts file: " << KNOWN_HOSTS_FILE << std::endl;
        return false;
    }
    for (const auto& pair : known_hosts) {
        outfile << pair.first << " " << pair.second << std::endl;
    }
    return true;
}

std::string get_server_address_string(const sockaddr_in* addr) {
     char ip_str[INET_ADDRSTRLEN];
     inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
     return std::string(ip_str) + ":" + std::to_string(ntohs(addr->sin_port));
}




void error_exit(const std::string& msg) {
    std::cerr << msg << std::endl;
    print_openssl_errors("OpenSSL errors during execution"); 
    cleanup_openssl();
    exit(EXIT_FAILURE);
}

void print_openssl_errors(const std::string& msg) {
    if (ERR_peek_error() == 0) return; 

    std::cerr << "[OpenSSL Error] " << msg << ":" << std::endl;
    ERR_print_errors_fp(stderr);
    ERR_clear_error(); 
}

std::string expand_path(const std::string& path) {
    wordexp_t p;
    if (wordexp(path.c_str(), &p, 0) != 0) {
        return "";
    }
    std::string expanded_path = p.we_wordv[0];
    wordfree(&p);
    return expanded_path;
}

std::string getCurrentTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    struct tm localTime;

#if defined(_WIN32)
    localtime_s(&localTime, &time);
#else
    localtime_r(&time, &localTime);
#endif

    std::stringstream ss;
    ss << std::put_time(&localTime, "%Y-%m-%d_%H-%M-%S");

    return ss.str();
}