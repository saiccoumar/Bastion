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
#include <pty.h>     // Include for forkpty
#include <algorithm> // For std::max
#include <errno.h>   // For errno
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "common.h"

#define PORT 2022
const std::string SERVER_STATIC_KEY_FILE = "server_static_key.pem";

EVP_PKEY *server_static_key = NULL;

void handle_client(int client_sock, sockaddr_in client_addr)
{
    print_openssl_errors("Start handle_client for bastion-srv");

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
    p_client_ephemeral_pubkey = NULL;         // Avoid dangling pointer issues

    // Receive encrypted target
    std::vector<unsigned char> encrypted_target_bytes = receive_encrypted_message(client_sock, session_key); //
    if (encrypted_target_bytes.empty())
    {
        std::cerr << "[Server SRV] Failed to receive encrypted target or decryption failed from "
                  << get_server_address_string(&client_addr) << "." << std::endl;
        close(client_sock);
        delete[] session_key;
        return;
    }
    std::string target(encrypted_target_bytes.begin(), encrypted_target_bytes.end());
    std::cout << "[Server SRV] Decrypted target '" << target << "' from " << get_server_address_string(&client_addr) << "." << std::endl;

    pid_t pid = fork(); //
    if (pid < 0)
    {
        std::cerr << "[Server SRV Error] Fork failed for client " << get_server_address_string(&client_addr) << ": " << strerror(errno) << std::endl;
        close(client_sock);
        delete[] session_key; // Clean up session key if fork fails
        return;
    }

    if (pid == 0)
    {                                                                   // Child process: This process will proxy data
        int master_fd;                                                  // File descriptor for the master side of the pseudo-terminal
        pid_t ssh_pid = forkpty(&master_fd, nullptr, nullptr, nullptr); //
        if (ssh_pid < 0)
        {
            perror("[Server SRV Error] forkpty failed for SSH process");
            close(client_sock); // Close client connection before exiting
            delete[] session_key;
            exit(EXIT_FAILURE);
        }

        if (ssh_pid == 0)
        { // Grandchild process: This becomes the SSH client
            // Close inherited client socket descriptor as SSH process doesn't need it
            close(client_sock);

            unsetenv("DISPLAY");
            unsetenv("SSH_ASKPASS");
            execlp("ssh", "ssh", "-tt", target.c_str(), nullptr); //
            // If execlp returns, it's an error
            perror("[Server SRV Error] execlp ssh failed");
            exit(EXIT_FAILURE);
        }
        else
        { // Child process (still): This is the server-side proxy managing PTY
            std::cout << "[Server SRV] SSH process forked with PID " << ssh_pid << " for target '" << target
                      << "' (client: " << get_server_address_string(&client_addr) << ")." << std::endl;

            fd_set read_fds;
            char buffer[4096]; // Buffer for data from PTY to client
            ssize_t bytes_read;
            bool running = true;

            while (running)
            {
                FD_ZERO(&read_fds);
                FD_SET(client_sock, &read_fds); // Monitor client socket for data
                FD_SET(master_fd, &read_fds);   // Monitor SSH PTY for data
                int max_fd = std::max(client_sock, master_fd);

                int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);
                if (activity < 0)
                {
                    if (errno == EINTR)
                        continue; // Interrupted by a signal, restart select
                    perror("[Server SRV Error] select failed in proxy");
                    running = false;
                    break;
                }
                if (activity == 0)
                    continue; // Should not happen with NULL timeout

                // Data from the SSH process (master_fd) to the client (client_sock)
                if (FD_ISSET(master_fd, &read_fds))
                {
                    bytes_read = read(master_fd, buffer, sizeof(buffer)); //
                    if (bytes_read <= 0)
                    { // EOF or error from SSH process
                        if (bytes_read < 0)
                            perror("[Server SRV Info] read from SSH PTY failed");
                        else
                            std::cout << "[Server SRV Info] SSH PTY (master_fd) closed (EOF) for target '" << target << "'." << std::endl;
                        running = false;
                        break;
                    }
                    std::vector<unsigned char> plaintext(buffer, buffer + bytes_read);
                    if (!send_encrypted_message(client_sock, plaintext, session_key))
                    { //
                        std::cerr << "[Server SRV] Failed to send encrypted data to client "
                                  << get_server_address_string(&client_addr) << ": " << strerror(errno) << std::endl;
                        running = false;
                        break;
                    }
                }

                // Data from the client (client_sock) to the SSH process (master_fd)
                if (FD_ISSET(client_sock, &read_fds))
                {
                    std::vector<unsigned char> decrypted_data = receive_encrypted_message(client_sock, session_key); //
                    if (decrypted_data.empty())
                    { // Decryption failed or client closed connection
                        if (errno != 0 && errno != ECONNRESET && errno != EPIPE)
                        { // Check if it was an actual error vs clean close
                            std::cerr << "[Server SRV] Failed to receive/decrypt data from client "
                                      << get_server_address_string(&client_addr) << ": " << strerror(errno) << std::endl;
                        }
                        else
                        {
                            std::cout << "[Server SRV Info] Client " << get_server_address_string(&client_addr)
                                      << " closed connection or sent no data for target '" << target << "'." << std::endl;
                        }
                        running = false;
                        break;
                    }
                    if (write(master_fd, decrypted_data.data(), decrypted_data.size()) < 0)
                    { //
                        perror("[Server SRV Error] Failed to write to SSH process PTY");
                        running = false;
                        break;
                    }
                }
            } // end while(running)

            std::cout << "[Server SRV] Proxy loop terminated for target '" << target
                      << "' (client: " << get_server_address_string(&client_addr) << ")." << std::endl;

            // Close descriptors
            close(master_fd);   // This will typically send SIGHUP to the PTY slave (SSH)
            close(client_sock); // Close client socket

            // Wait for the SSH process to finish
            int status = 0;
            waitpid(ssh_pid, &status, 0); //
            if (WIFEXITED(status))
            {
                std::cout << "[Server SRV] SSH process (PID " << ssh_pid << ") for '" << target << "' exited with status " << WEXITSTATUS(status) << "." << std::endl;
            }
            else if (WIFSIGNALED(status))
            {
                std::cout << "[Server SRV] SSH process (PID " << ssh_pid << ") for '" << target << "' killed by signal " << WTERMSIG(status) << "." << std::endl;
            }
            else
            {
                std::cout << "[Server SRV] SSH process (PID " << ssh_pid << ") for '" << target << "' finished (status: " << status << ")." << std::endl;
            }

            delete[] session_key; // Child proxy process cleans up the session key
            exit(EXIT_SUCCESS);   // Child proxy process exits
        }
    }
    else
    {
        close(client_sock);
        std::cout << "[Server SRV] Parent (handle_client thread) forked child PID " << pid << " to handle client "
                  << get_server_address_string(&client_addr) << " for target '" << target << "'. Parent thread continuing." << std::endl;
    }
}

int main()
{
    init_openssl();

    server_static_key = load_pkey_pem(SERVER_STATIC_KEY_FILE, false);
    if (!server_static_key)
    {
        std::cerr << "[Server] Static key not found. Generating new key pair..." << std::endl;

        // Generate ECDSA key with explicit parameters
        server_static_key = EVP_PKEY_new();
        if (!server_static_key)
        {
            error_exit("[Server] Failed to create EVP_PKEY structure");
        }

        EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ec_key)
        {
            EVP_PKEY_free(server_static_key);
            error_exit("[Server] Failed to create EC_KEY structure");
        }

        if (!EC_KEY_generate_key(ec_key))
        {
            EC_KEY_free(ec_key);
            EVP_PKEY_free(server_static_key);
            error_exit("[Server] Failed to generate EC key pair");
        }

        if (!EVP_PKEY_assign_EC_KEY(server_static_key, ec_key))
        {
            EC_KEY_free(ec_key);
            EVP_PKEY_free(server_static_key);
            error_exit("[Server] Failed to assign EC key to EVP_PKEY");
        }

        // Save the key in PEM format
        FILE *f = fopen(SERVER_STATIC_KEY_FILE.c_str(), "wb");
        if (!f)
        {
            EVP_PKEY_free(server_static_key);
            error_exit("[Server] Failed to open file for writing static key");
        }

        if (!PEM_write_PrivateKey(f, server_static_key, NULL, NULL, 0, NULL, NULL))
        {
            fclose(f);
            EVP_PKEY_free(server_static_key);
            error_exit("[Server] Failed to write static key to file");
        }

        fclose(f);
        std::cout << "[Server] Generated and saved new static key pair to " << SERVER_STATIC_KEY_FILE << std::endl;
        std::cout << "[Server] Static Key Fingerprint: " << calculate_public_key_fingerprint(server_static_key) << std::endl;
    }
    else
    {
        std::cout << "[Server] Loaded static key from " << SERVER_STATIC_KEY_FILE << std::endl;
        std::cout << "[Server] Static Key Fingerprint: " << calculate_public_key_fingerprint(server_static_key) << std::endl;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error_exit("[Server SRV Error] Socket creation failed");

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("[Server SRV Warning] setsockopt(SO_REUSEADDR) failed");
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        error_exit("[Server SRV Error] Bind failed");

    if (listen(sockfd, 10) < 0) // Increased backlog slightly
        error_exit("[Server SRV Error] Listen failed");

    std::cout << "[Server SRV] SSH proxy server listening securely on port " << PORT << std::endl;

    while (true)
    {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        // The TODO for checking client key/fingerprint was here, but it's better done inside handle_client.
        int client_sock = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0)
        {
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