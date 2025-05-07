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
#include <map>
#include "common.h" 

#define PORT 2022
const std::string SERVER_STATIC_KEY_FILE = "server_static_key.pem";

EVP_PKEY* server_static_key = NULL;
unsigned char session_key[AES_KEY_SIZE];


bool perform_server_handshake(int client_sock, const sockaddr_in* client_addr, EVP_PKEY*& client_ephemeral_pubkey) {
    print_openssl_errors("Start server handshake");
    
    EVP_PKEY* server_ephemeral_key = generate_ecdh_key();
    if (!server_ephemeral_key) {
        std::cerr << "[Server] Failed to generate ephemeral key." << std::endl;
        return false;
    }

    
    std::vector<unsigned char> static_pub_der = get_public_key_der(server_static_key);
    std::vector<unsigned char> ephemeral_pub_der = get_public_key_der(server_ephemeral_key);

    if (static_pub_der.empty() || ephemeral_pub_der.empty()) {
        EVP_PKEY_free(server_ephemeral_key);
        return false;
    }

    
    if (!send_message(client_sock, static_pub_der)) {
        std::cerr << "[Server] Failed to send static public key." << std::endl;
        EVP_PKEY_free(server_ephemeral_key);
        return false;
    }

    
    if (!send_message(client_sock, ephemeral_pub_der)) {
        std::cerr << "[Server] Failed to send ephemeral public key." << std::endl;
        EVP_PKEY_free(server_ephemeral_key);
        return false;
    }
     std::cout << "[Server] Sent static and ephemeral public keys." << std::endl;


    
    std::vector<unsigned char> client_ephemeral_pub_der = receive_message(client_sock);
    if (client_ephemeral_pub_der.empty()) {
        std::cerr << "[Server] Failed to receive client ephemeral public key." << std::endl;
        EVP_PKEY_free(server_ephemeral_key);
        return false;
    }
    std::cout << "[Server] Received client ephemeral public key." << std::endl;


    
    client_ephemeral_pubkey = create_pkey_from_public_der(client_ephemeral_pub_der);
    if (!client_ephemeral_pubkey) {
        std::cerr << "[Server] Failed to create EVP_PKEY from client public key DER." << std::endl;
        EVP_PKEY_free(server_ephemeral_key);
        return false;
    }

    
    std::vector<unsigned char> shared_secret = derive_shared_secret(server_ephemeral_key, client_ephemeral_pubkey);
    EVP_PKEY_free(server_ephemeral_key); 

    if (shared_secret.empty()) {
        std::cerr << "[Server] Failed to derive shared secret." << std::endl;
        EVP_PKEY_free(client_ephemeral_pubkey); 
        client_ephemeral_pubkey = NULL;
        return false;
    }
     std::cout << "[Server] Derived shared secret (size: " << shared_secret.size() << ")." << std::endl;


    
    
    std::vector<unsigned char> hashed_secret = calculate_sha256(shared_secret);
    if (hashed_secret.size() < AES_KEY_SIZE) {
        std::cerr << "[Server] Hashed shared secret is too short for AES key." << std::endl;
        EVP_PKEY_free(client_ephemeral_pubkey);
        client_ephemeral_pubkey = NULL;
        return false;
    }
    memcpy(session_key, hashed_secret.data(), AES_KEY_SIZE);
     std::cout << "[Server] Derived session key." << std::endl;

    return true;
}

void handle_client(int client_sock, sockaddr_in client_addr) {
    print_openssl_errors("Start handle_client");

    EVP_PKEY* client_ephemeral_pubkey = NULL;

    
    if (!perform_server_handshake(client_sock, &client_addr, client_ephemeral_pubkey)) {
        std::cerr << "[Server] Handshake failed for client." << std::endl;
        close(client_sock);
        EVP_PKEY_free(client_ephemeral_pubkey); 
        return;
    }
     std::cout << "[Server] Handshake successful. Starting secure communication." << std::endl;

    EVP_PKEY_free(client_ephemeral_pubkey); 


    
    std::vector<unsigned char> encrypted_target_bytes = receive_encrypted_message(client_sock, session_key);
    if (encrypted_target_bytes.empty()) {
        std::cerr << "[Server] Failed to receive encrypted target or decryption failed." << std::endl;
        close(client_sock);
        return;
    }

    std::string target(encrypted_target_bytes.begin(), encrypted_target_bytes.end());
    std::cout << "[Server] Decrypted target: " << target << std::endl;

    
    pid_t pid = fork();
    if (pid < 0) {
         std::cerr << "[Server Error] Fork failed: " << strerror(errno) << std::endl;
         close(client_sock);
         return;
    }

    if (pid == 0) {
        

        
        dup2(client_sock, STDIN_FILENO);
        dup2(client_sock, STDOUT_FILENO);
        dup2(client_sock, STDERR_FILENO);

        
        close(client_sock);

        
        execlp("ssh", "ssh", "-tt", target.c_str(), nullptr);

        
        perror("execlp ssh failed");
        exit(EXIT_FAILURE); 
    } else {
        
        
        close(client_sock);

        
        int status;
        waitpid(pid, &status, 0);
        std::cout << "[Server] SSH process for target '" << target << "' finished with status " << status << "." << std::endl;
    }
}

int main() {
    init_openssl();

    
    server_static_key = load_pkey_pem(SERVER_STATIC_KEY_FILE, false); 
    if (!server_static_key) {
        std::cerr << "[Server] Static key not found. Generating new key pair..." << std::endl;
        server_static_key = generate_ecdsa_key();
        if (!server_static_key) {
            error_exit("[Server] Failed to generate static key.");
        }
        if (!save_pkey_pem(server_static_key, SERVER_STATIC_KEY_FILE, false)) { 
             EVP_PKEY_free(server_static_key);
             server_static_key = NULL;
             error_exit("[Server] Failed to save static key.");
        }
        std::cout << "[Server] Generated and saved new static key pair to " << SERVER_STATIC_KEY_FILE << std::endl;
         std::cout << "[Server] Static Key Fingerprint: " << calculate_public_key_fingerprint(server_static_key) << std::endl;
    } else {
         std::cout << "[Server] Loaded static key from " << SERVER_STATIC_KEY_FILE << std::endl;
         std::cout << "[Server] Static Key Fingerprint: " << calculate_public_key_fingerprint(server_static_key) << std::endl;
    }


    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error_exit("[Server Error] Socket creation failed");

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        error_exit("[Server Error] Bind failed");

    if (listen(sockfd, 5) < 0)
        error_exit("[Server Error] Listen failed");

    std::cout << "[Server] Listening securely on port " << PORT << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            std::cerr << "[Server] Accept failed: " << strerror(errno) << std::endl;
            continue;
        }

        std::cout << "[Server] Connection accepted from " << get_server_address_string(&client_addr) << std::endl;
        
        
        std::thread(handle_client, client_sock, client_addr).detach();
    }

    close(sockfd);
    EVP_PKEY_free(server_static_key);
    cleanup_openssl();
    return 0;
}