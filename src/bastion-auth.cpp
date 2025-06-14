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
#include <sys/stat.h> // Include for mkdir and stat
#include <fstream>
#include <sstream>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "common.h" 

#define PORT 2023
const std::string SERVER_STATIC_KEY_FILE = "server_static_key.pem";
const std::string SERVER_KEY_PATH = "~/.ssh/id_rsa_bastion_auth";

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


    // Perform handshake
    
    EVP_PKEY *p_client_ephemeral_pubkey = NULL; // To be populated by perform_server_handshake
    unsigned char *session_key = perform_server_handshake(client_sock, &client_addr,
                                                          server_static_key, p_client_ephemeral_pubkey);

    if (!session_key)
    {
        std::cerr << "[Server SRV] Handshake failed for client: " << get_server_address_string(&client_addr) << std::endl;
        close(client_sock);
        EVP_PKEY_free(p_client_ephemeral_pubkey);
        return;
    }
    std::cout << "[Server SRV] Handshake successful with " << get_server_address_string(&client_addr) << "." << std::endl;

    // --- START PASSWORD AUTHENTICATION ---
    if (p_client_ephemeral_pubkey)
    {
        std::string client_fingerprint = calculate_public_key_fingerprint(p_client_ephemeral_pubkey);
        std::cout << "[Server SRV] Client ephemeral public key fingerprint: SHA256:" << client_fingerprint << std::endl;


        // --- Client Authorization (Now with Password Auth) ---
        bool is_authorized = false;
        // Receive username
        std::vector<unsigned char> encrypted_username_bytes = receive_encrypted_message(client_sock, session_key);
        if (encrypted_username_bytes.empty())
        {
            std::cerr << "[Server SRV] Failed to receive username from " << get_server_address_string(&client_addr) << "." << std::endl;
        }
        else
        {
            std::string username(encrypted_username_bytes.begin(), encrypted_username_bytes.end());

            // Receive password
            std::vector<unsigned char> encrypted_password_bytes = receive_encrypted_message(client_sock, session_key);
            if (encrypted_password_bytes.empty())
            {
                std::cerr << "[Server SRV] Failed to receive password from " << get_server_address_string(&client_addr) << "." << std::endl;
            }
            else
            {
                std::string password(encrypted_password_bytes.begin(), encrypted_password_bytes.end());

                // --- PAM Authentication ---
                pam_handle_t *pamh = NULL;
                const char *pam_service_name = "sshd"; // Use the 'sshd' service for robust configuration
                struct pam_conv conv = {pam_conversation, (void *)password.c_str()};

                int retval = pam_start(pam_service_name, username.c_str(), &conv, &pamh);

                if (retval == PAM_SUCCESS)
                {
                    retval = pam_authenticate(pamh, 0); // Authenticate the user
                }

                if (retval == PAM_SUCCESS)
                {
                    retval = pam_acct_mgmt(pamh, 0); // Check if account is valid
                }

                if (retval == PAM_SUCCESS)
                {
                    std::cout << "[Server SRV] PAM authentication successful for user '" << username << "." << std::endl;
                    is_authorized = true;
                }
                else
                {
                    std::cerr << "[Server SRV] PAM authentication failed for user '" << username << "': " << pam_strerror(pamh, retval) << std::endl;
                }

                if (pamh)
                {
                    pam_end(pamh, retval);
                }
            }
        }

        // Send authorization status to client
        const char *auth_status_msg = is_authorized ? "AUTH_SUCCESS" : "AUTH_FAILURE";
        std::vector<unsigned char> auth_status_bytes(auth_status_msg, auth_status_msg + strlen(auth_status_msg));
        if (!send_encrypted_message(client_sock, auth_status_bytes, session_key))
        {
            std::cerr << "[Server SRV] Failed to send auth status to client." << std::endl;
            is_authorized = false; // Prevent proceeding if we can't communicate status
        }

        if (!is_authorized)
        {
            std::cerr << "[Server SRV] Authorization failed. Closing connection for " << get_server_address_string(&client_addr) << "." << std::endl;
            close(client_sock);
            delete[] session_key;
            EVP_PKEY_free(p_client_ephemeral_pubkey);
            return;
        }

        // -- END CLIENT PASSWORD AUTHENTICATION
    }
    else
    {
        std::cerr << "[Server SRV] Warning: Could not obtain client ephemeral public key for authorization check for "
                  << get_server_address_string(&client_addr) << "." << std::endl;
        // Depending on security policy, you might deny service here.
    }
    EVP_PKEY_free(p_client_ephemeral_pubkey); // Free client's key after check (or if NULL)
    p_client_ephemeral_pubkey = NULL;

    
    // GENERATE KEY:

    // Replace absolute paths with expanded path
    std::string key_path = expand_path(SERVER_KEY_PATH);
    std::string pub_key_path = key_path + ".pub";

    // Check if the key exists, otherwise generate it
    struct stat buffer;
    if (stat(key_path.c_str(), &buffer) != 0) {
        std::cout << "[Client] SSH key not found. Generating a new one at " << key_path << std::endl;
        std::string command = "ssh-keygen -t rsa -b 4096 -f " + key_path + " -N '' -C 'bastion-client-server'";
        if (system(command.c_str()) != 0) {
            std::cerr << "[Client] Failed to generate SSH key. Please ensure ssh-keygen is installed." << std::endl;
            return;
        }
    }

    // Read the server's public key from the file
    std::ifstream pub_key_file(pub_key_path);
    if (!pub_key_file) {
        std::cerr << "[Client] Could not read public key file: " << pub_key_path << std::endl;
        return;
    }
    std::string pub_key_str((std::istreambuf_iterator<char>(pub_key_file)), std::istreambuf_iterator<char>());


    // ACTION A: Receive client's public key
    std::vector<unsigned char> client_pubkey_bytes = receive_encrypted_message(client_sock, session_key);
    if (client_pubkey_bytes.empty()) {
        std::cerr << "[Server] Failed to receive bastion's public key." << std::endl;
    } else {
        std::cout << "[Server] Received bastion's public key." << std::endl;
        std::string bastion_pubkey(client_pubkey_bytes.begin(), client_pubkey_bytes.end());

        // Add the bastion's key to authorized_keys file
        std::string ssh_dir = expand_path("~/.ssh");
        std::string auth_keys_path = ssh_dir + "/authorized_keys";

        // Open authorized_keys file in append mode
        std::ofstream auth_keys(auth_keys_path, std::ios::app);
        if (!auth_keys.is_open())
        {
            std::cerr << "[Server] Failed to open authorized_keys: " << strerror(errno) << std::endl;
        }
        else
        {
            auth_keys << bastion_pubkey;
            if (bastion_pubkey.back() != '\n')
                auth_keys << "\n";
            std::cout << "[Server] Bastion's public key added to " << auth_keys_path << std::endl;
        }

        auth_keys.close();
        chmod(auth_keys_path.c_str(), 0600); // Set proper permissions for the keys file
        chmod(ssh_dir.c_str(), 0700);        // Set proper permissions for the .ssh directory
    }

    // ACTION B: Send the server's public key to the client
    std::vector<unsigned char> pub_key_bytes(pub_key_str.begin(), pub_key_str.end());
    if (!send_encrypted_message(client_sock, pub_key_bytes, session_key)) {
        std::cerr << "[Client] Failed to send public key to auth server." << std::endl;
    } else {
        std::cout << "[Client] Successfully sent public key to the bastion." << std::endl;
    }

    // Send a success message to the logs
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
        
        // Generate ECDSA key with explicit parameters
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

        // Save the key in PEM format
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

    if (listen(sockfd, 10) < 0) // Increased backlog slightly
        error_exit("[Server SRV Error] Listen failed");

    std::cout << "[Server SRV] SSH proxy server listening securely on port " << PORT << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        // The TODO for checking client key/fingerprint was here, but it's better done inside handle_client.
        int client_sock = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("[Server SRV Error] Accept failed"); // Log error but continue server operation
            continue;
        }
        std::cout << "[Server SRV] Connection accepted from " << get_server_address_string(&client_addr) << std::endl;

        // Detach thread to handle client connection concurrently
        std::thread(handle_client, client_sock, client_addr).detach();
    }

    close(sockfd);
    EVP_PKEY_free(server_static_key);
    cleanup_openssl();
    return 0;
}