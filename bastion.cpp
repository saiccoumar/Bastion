#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <cstring>
#include <sys/wait.h>
#include <vector>
#include <map>

#include "common.h" 

#define PORT 2022

unsigned char session_key[AES_KEY_SIZE];


bool perform_client_handshake(int sock, const std::string& server_address_string) {
    print_openssl_errors("Start client handshake");
    
    EVP_PKEY* client_ephemeral_key = generate_ecdh_key();
    if (!client_ephemeral_key) {
        std::cerr << "[Client] Failed to generate ephemeral key." << std::endl;
        return false;
    }

    
    std::vector<unsigned char> ephemeral_pub_der = get_public_key_der(client_ephemeral_key);
    if (ephemeral_pub_der.empty()) {
        EVP_PKEY_free(client_ephemeral_key);
        return false;
    }

    if (!send_message(sock, ephemeral_pub_der)) {
        std::cerr << "[Client] Failed to send ephemeral public key." << std::endl;
        EVP_PKEY_free(client_ephemeral_key);
        return false;
    }
     std::cout << "[Client] Sent ephemeral public key." << std::endl;


    
    std::vector<unsigned char> server_static_pub_der = receive_message(sock);
    if (server_static_pub_der.empty()) {
        std::cerr << "[Client] Failed to receive server static public key." << std::endl;
        EVP_PKEY_free(client_ephemeral_key);
        return false;
    }
     std::cout << "[Client] Received server static public key." << std::endl;


    std::vector<unsigned char> server_ephemeral_pub_der = receive_message(sock);
    if (server_ephemeral_pub_der.empty()) {
        std::cerr << "[Client] Failed to receive server ephemeral public key." << std::endl;
        EVP_PKEY_free(client_ephemeral_key);
        return false;
    }
     std::cout << "[Client] Received server ephemeral public key." << std::endl;


    
    EVP_PKEY* server_static_pubkey = create_pkey_from_public_der(server_static_pub_der);
    EVP_PKEY* server_ephemeral_pubkey = create_pkey_from_public_der(server_ephemeral_pub_der);

    if (!server_static_pubkey || !server_ephemeral_pubkey) {
        std::cerr << "[Client] Failed to create EVP_PKEYs from server public keys." << std::endl;
        EVP_PKEY_free(client_ephemeral_key);
        EVP_PKEY_free(server_static_pubkey);
        EVP_PKEY_free(server_ephemeral_pubkey);
        return false;
    }

    
    std::string received_fingerprint = calculate_public_key_fingerprint(server_static_pubkey);
    std::map<std::string, std::string> known_hosts = read_known_hosts();

    auto it = known_hosts.find(server_address_string);

    if (it == known_hosts.end()) {
        
        std::cout << "The authenticity of host '" << server_address_string << "' can't be established." << std::endl;
        std::cout << "ECDSA key fingerprint is SHA256:" << received_fingerprint << "." << std::endl;
        
        
        std::cout << "Warning: Automatically adding '" << server_address_string << "' (ECDSA) to the list of known hosts." << std::endl;
        known_hosts[server_address_string] = received_fingerprint;
        if (!write_known_hosts(known_hosts)) {
            std::cerr << "[Client] Warning: Failed to save host key fingerprint." << std::endl;
        }
    } else {
        
        std::string stored_fingerprint = it->second;
        if (stored_fingerprint != received_fingerprint) {
            std::cerr << "[Client Error]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" << std::endl;
            std::cerr << "[Client Error]@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @" << std::endl;
            std::cerr << "[Client Error]@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" << std::endl;
            std::cerr << "[Client Error]IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!" << std::endl;
            std::cerr << "[Client Error]Someone could be eavesdropping on you right now (man-in-the-middle attack)!" << std::endl;
            std::cerr << "[Client Error]The fingerprint received from the server is SHA256:" << received_fingerprint << std::endl;
            std::cerr << "[Client Error]The stored fingerprint for " << server_address_string << " is SHA256:" << stored_fingerprint << std::endl;
            
            
            EVP_PKEY_free(client_ephemeral_key);
            EVP_PKEY_free(server_static_pubkey);
            EVP_PKEY_free(server_ephemeral_pubkey);
            return false; 
        }
        std::cout << "[Client] Host key fingerprint verified." << std::endl;
    }

    EVP_PKEY_free(server_static_pubkey); 


    
    std::vector<unsigned char> shared_secret = derive_shared_secret(client_ephemeral_key, server_ephemeral_pubkey);
    EVP_PKEY_free(client_ephemeral_key); 
    EVP_PKEY_free(server_ephemeral_pubkey); 

    if (shared_secret.empty()) {
        std::cerr << "[Client] Failed to derive shared secret." << std::endl;
        return false;
    }
    std::cout << "[Client] Derived shared secret (size: " << shared_secret.size() << ")." << std::endl;


    
    std::vector<unsigned char> hashed_secret = calculate_sha256(shared_secret);
    if (hashed_secret.size() < AES_KEY_SIZE) {
        std::cerr << "[Client] Hashed shared secret is too short for AES key." << std::endl;
        return false;
    }
    memcpy(session_key, hashed_secret.data(), AES_KEY_SIZE);
    std::cout << "[Client] Derived session key." << std::endl;

    return true; 
}

int main(int argc, char* argv[]) {
    init_openssl();

    if (argc != 3) {
        std::cerr << "Usage: bastion <server_ip> <user@target>\n";
        cleanup_openssl();
        return EXIT_FAILURE;
    }

    std::string server_ip = argv[1];
    std::string target = argv[2];

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) error_exit("[Client Error] Socket creation failed");

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
         close(sock);
         error_exit("[Client Error] Invalid server address");
    }

    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
         close(sock);
         error_exit("[Client Error] Could not connect to bastion server");
    }

    std::string server_address_string = get_server_address_string(&server_addr);
    std::cout << "[Client] Connected to " << server_address_string << ". Performing handshake..." << std::endl;

    
    if (!perform_client_handshake(sock, server_address_string)) {
        std::cerr << "[Client] Secure handshake failed. Aborting." << std::endl;
        close(sock);
        cleanup_openssl();
        return EXIT_FAILURE;
    }
     std::cout << "[Client] Handshake successful. Sending encrypted target." << std::endl;


    
    std::vector<unsigned char> target_bytes(target.begin(), target.end());
    if (!send_encrypted_message(sock, target_bytes, session_key)) {
        std::cerr << "[Client] Failed to send encrypted target." << std::endl;
        close(sock);
        cleanup_openssl();
        return EXIT_FAILURE;
    }
     std::cout << "[Client] Encrypted target sent. Starting secure proxy." << std::endl;


    
    pid_t pid = fork();
     if (pid < 0) {
         std::cerr << "[Client Error] Fork failed: " << strerror(errno) << std::endl;
         close(sock);
         cleanup_openssl();
         return EXIT_FAILURE;
    }


    if (pid == 0) {
        
        char buf[256];
        while (true) {
            ssize_t n = read(STDIN_FILeno, buf, sizeof(buf));
            if (n <= 0) break; 

            std::vector<unsigned char> plaintext(buf, buf + n);
            if (!send_encrypted_message(sock, plaintext, session_key)) {
                std::cerr << "[Client Child] Failed to send encrypted data." << std::endl;
                break; 
            }
        }
        
        close(sock);
        exit(0); 
    } else {
        
        while (true) {
            std::vector<unsigned char> plaintext = receive_encrypted_message(sock, session_key);
            if (plaintext.empty()) {
                 
                 if (!plaintext.empty() || errno != 0) { 
                      
                      std::cerr << "[Client Parent] Error receiving/decrypting data." << std::endl;
                 } else {
                      
                      std::cout << "[Client Parent] Server closed connection." << std::endl;
                 }
                break; 
            }
            
            write(STDOUT_FILENO, plaintext.data(), plaintext.size());
        }
        
        waitpid(pid, nullptr, 0);
    }

    
    close(sock);
    cleanup_openssl();
    return 0;
}