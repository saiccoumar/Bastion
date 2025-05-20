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
#include <pty.h> // Include for forkpty

#include "common.h" 

#define PORT 2022
const std::string SERVER_STATIC_KEY_FILE = "server_static_key.pem";

EVP_PKEY* server_static_key = NULL;
// unsigned char session_key[AES_KEY_SIZE];



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

    std::vector<unsigned char> encrypted_target_bytes = receive_encrypted_message(client_sock, session_key);
    if (encrypted_target_bytes.empty()) {
        std::cerr << "[Server] Failed to receive encrypted target or decryption failed." << std::endl;
        close(client_sock);
        delete[] session_key;
        return;
    }

    std::string target(encrypted_target_bytes.begin(), encrypted_target_bytes.end());
    std::cout << "[Server] Decrypted target: " << target << std::endl;

    
    pid_t pid = fork();
    if (pid < 0) {
         std::cerr << "[Server Error] Fork failed: " << strerror(errno) << std::endl;
         close(client_sock);
         delete[] session_key;
         return;
    }

    if (pid == 0) {
        // Child process
        int pipe_in[2], pipe_out[2];
        if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0) {
            perror("[Server Error] pipe creation failed");
            close(client_sock);
            delete[] session_key;
            exit(EXIT_FAILURE);
        }

        int master_fd; // File descriptor for the master side of the pseudo-terminal
        pid_t ssh_pid = forkpty(&master_fd, nullptr, nullptr, nullptr);
        if (ssh_pid < 0) {
            perror("[Server Error] forkpty failed for SSH process");
            close(client_sock);
            delete[] session_key;
            exit(EXIT_FAILURE);
        }

        if (ssh_pid == 0) {
            // Grandchild process (SSH)
            unsetenv("DISPLAY");
            unsetenv("SSH_ASKPASS");

            // Execute the SSH command
            execlp("ssh", "ssh", "-tt", target.c_str(), nullptr);

            // If execlp fails, log the error and exit
            perror("[Server Error] execlp ssh failed");
            exit(EXIT_FAILURE);
        } else {
            // Child process (Server-side proxy)
            close(pipe_in[0]);  // Close read end of input pipe
            close(pipe_out[1]); // Close write end of output pipe

            // Use `select` for bidirectional communication
            fd_set read_fds;
            int max_fd = std::max(client_sock, master_fd);

            char buffer[4096];
            ssize_t bytes_read;

            while (true) {
                FD_ZERO(&read_fds);
                FD_SET(client_sock, &read_fds);  // Monitor client socket
                FD_SET(master_fd, &read_fds);   // Monitor SSH PTY

                if (select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr) < 0) {
                    perror("[Server Error] select failed");
                    break;
                }

                // Data from the SSH process to the client
                if (FD_ISSET(master_fd, &read_fds)) {
                    bytes_read = read(master_fd, buffer, sizeof(buffer));
                    if (bytes_read <= 0) break; // EOF or error

                    std::vector<unsigned char> plaintext(buffer, buffer + bytes_read);
                    if (!send_encrypted_message(client_sock, plaintext, session_key)) {
                        std::cerr << "[Server] Failed to send encrypted data to client." << std::endl;
                        break;
                    }
                }

                // Data from the client to the SSH process
                if (FD_ISSET(client_sock, &read_fds)) {
                    std::vector<unsigned char> encrypted_data = receive_encrypted_message(client_sock, session_key);
                    if (encrypted_data.empty()) {
                        std::cerr << "[Server] Failed to receive encrypted data from client." << std::endl;
                        break;
                    }

                    // Write decrypted data to the SSH process
                    if (write(master_fd, encrypted_data.data(), encrypted_data.size()) < 0) {
                        perror("[Server Error] Failed to write to SSH process");
                        break;
                    }
                }
            }

            // Close pipes and socket
            close(pipe_in[1]);
            close(master_fd);
            close(client_sock);

            // Wait for the SSH process to finish
            int status;
            waitpid(ssh_pid, &status, 0);
            std::cout << "[Server] SSH process finished with status " << status << "." << std::endl;
            delete[] session_key;
            exit(EXIT_SUCCESS);
        }
    }
    delete[] session_key;
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