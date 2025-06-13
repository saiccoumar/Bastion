#include <libssh/libssh.h> 
#include <libssh/callbacks.h> 
#include <libssh/server.h> 
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <sys/wait.h>
#include <thread>
#include <vector>
#include <pty.h> 
#include <sys/stat.h> 
#include <fstream>
#include <sstream>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "common.h" 

#define PORT 2023
const std::string SERVER_STATIC_KEY_FILE = "server_static_key.pem";

EVP_PKEY* server_static_key = NULL;


volatile sig_atomic_t running = 1;

void signal_handler(int signum) {
    running = 0;
}

std::vector<unsigned char> string_to_vector(const std::string& str) {
    return std::vector<unsigned char>(str.begin(), str.end());
}

void handle_client(int client_sock, sockaddr_in client_addr) {
    print_openssl_errors("Start handle_client");

    EVP_PKEY* client_ephemeral_pubkey = NULL;
    
    unsigned char* session_key = perform_server_handshake(client_sock, &client_addr, 
                                                        server_static_key, client_ephemeral_pubkey);
    
    if (!session_key) {
        std::cerr << "[Server] Handshake failed for client." << std::endl;
        close(client_sock);
        EVP_PKEY_free(client_ephemeral_pubkey);
        return;
    }
    std::cout << "[Server] Handshake successful. Starting secure communication." << std::endl;

    EVP_PKEY_free(client_ephemeral_pubkey);


    

    

    
    const char* home = getenv("HOME");
    if (!home) {
        std::cerr << "[Server] Could not get HOME directory" << std::endl;
        return;
    }
    std::string ssh_dir = std::string(home) + "/.ssh";
    std::string auth_keys_path = ssh_dir + "/authorized_keys";

    
    struct stat st;
    if (stat(ssh_dir.c_str(), &st) == -1) {
        if (mkdir(ssh_dir.c_str(), 0700) == -1) {
            std::string error_msg = "Failed to create .ssh directory: " + std::string(strerror(errno));
            std::vector<unsigned char> error_vec(error_msg.begin(), error_msg.end());
            send_encrypted_message(client_sock, error_vec, session_key);
            close(client_sock);
            delete[] session_key;
            return;
        }
    }

    
    std::vector<unsigned char> client_pubkey_bytes = receive_encrypted_message(client_sock, session_key);
    if (client_pubkey_bytes.empty()) {
        std::cerr << "[Server] Failed to receive client's public key" << std::endl;
        close(client_sock);
        delete[] session_key;
        return;
    }
    std::string client_pubkey(client_pubkey_bytes.begin(), client_pubkey_bytes.end());

    
    
    std::ofstream auth_keys(auth_keys_path, std::ios::app);
    if (!auth_keys.is_open()) {
        std::string error_msg = "Failed to open authorized_keys: " + std::string(strerror(errno));
        std::vector<unsigned char> error_vec(error_msg.begin(), error_msg.end());
        send_encrypted_message(client_sock, error_vec, session_key);
        close(client_sock);
        delete[] session_key;
        return;
    }
    auth_keys << client_pubkey << "\n";
    auth_keys.close();
    chmod(auth_keys_path.c_str(), 0600);

    
    if (stat("/etc/ssh/ssh_host_rsa_key", &st) == -1 || 
        stat("/etc/ssh/ssh_host_ed25519_key", &st) == -1) {
        if (system("ssh-keygen -A") != 0) {
            std::string error_msg = "Failed to generate host keys";
            std::vector<unsigned char> error_vec(error_msg.begin(), error_msg.end());
            send_encrypted_message(client_sock, error_vec, session_key);
            close(client_sock);
            delete[] session_key;
            return;
        }
    }

    
    std::ifstream server_key_file("/etc/ssh/ssh_host_rsa_key.pub");
    if (!server_key_file.is_open()) {
        std::string error_msg = "Failed to read server public key";
        std::vector<unsigned char> error_vec(error_msg.begin(), error_msg.end());
        send_encrypted_message(client_sock, error_vec, session_key);
        close(client_sock);
        delete[] session_key;
        return;
    }

    std::stringstream buffer;
    buffer << server_key_file.rdbuf();
    std::string server_pubkey = buffer.str();
    server_key_file.close();

    if (!send_encrypted_message(client_sock, string_to_vector(server_pubkey), session_key)) {
        std::cerr << "[Server] Failed to send server public key" << std::endl;
        close(client_sock);
        delete[] session_key;
        return;
    }

    std::string success_msg = "Key exchange completed";
    std::vector<unsigned char> success_vec(success_msg.begin(), success_msg.end());
    if (!send_encrypted_message(client_sock, success_vec, session_key)) {
        std::cerr << "[Server] Failed to send completion message" << std::endl;
        close(client_sock);
        delete[] session_key;
        return;
    }

    std::cout << "[Server] SSH key exchange completed successfully" << std::endl;


    
    delete[] session_key;
}

int main() {
    init_openssl();

    server_static_key = load_pkey_pem(SERVER_STATIC_KEY_FILE, false);
    if (!server_static_key) {
        std::cerr << "[Server] Static key not found. Generating new key pair..." << std::endl;
        
        
        server_static_key = EVP_PKEY_new();
        if (!server_static_key) {
            error_exit("[Server] Failed to create EVP_PKEY structure");
        }

        EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ec_key) {
            EVP_PKEY_free(server_static_key);
            error_exit("[Server] Failed to create EC_KEY structure");
        }

        if (!EC_KEY_generate_key(ec_key)) {
            EC_KEY_free(ec_key);
            EVP_PKEY_free(server_static_key);
            error_exit("[Server] Failed to generate EC key pair");
        }

        if (!EVP_PKEY_assign_EC_KEY(server_static_key, ec_key)) {
            EC_KEY_free(ec_key);
            EVP_PKEY_free(server_static_key);
            error_exit("[Server] Failed to assign EC key to EVP_PKEY");
        }

        
        FILE* f = fopen(SERVER_STATIC_KEY_FILE.c_str(), "wb");
        if (!f) {
            EVP_PKEY_free(server_static_key);
            error_exit("[Server] Failed to open file for writing static key");
        }

        if (!PEM_write_PrivateKey(f, server_static_key, NULL, NULL, 0, NULL, NULL)) {
            fclose(f);
            EVP_PKEY_free(server_static_key);
            error_exit("[Server] Failed to write static key to file");
        }

        fclose(f);
        std::cout << "[Server] Generated and saved new static key pair to " << SERVER_STATIC_KEY_FILE << std::endl;
        std::cout << "[Server] Static Key Fingerprint: " << calculate_public_key_fingerprint(server_static_key) << std::endl;
    } else {
        std::cout << "[Server] Loaded static key from " << SERVER_STATIC_KEY_FILE << std::endl;
        std::cout << "[Server] Static Key Fingerprint: " << calculate_public_key_fingerprint(server_static_key) << std::endl;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error_exit("[Server SRV Error] Socket creation failed");

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[Server SRV Warning] setsockopt(SO_REUSEADDR) failed");
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        error_exit("[Server SRV Error] Bind failed");

    if (listen(sockfd, 10) < 0) 
        error_exit("[Server SRV Error] Listen failed");

    std::cout << "[Server SRV] SSH proxy server listening securely on port " << PORT << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        
        int client_sock = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("[Server SRV Error] Accept failed"); 
            continue;
        }
        std::cout << "[Server SRV] Connection accepted from " << get_server_address_string(&client_addr) << std::endl;

        
        std::thread(handle_client, client_sock, client_addr).detach();
    }

    close(sockfd);
    EVP_PKEY_free(server_static_key);
    cleanup_openssl();
    return 0;
}