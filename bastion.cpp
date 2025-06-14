#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <fstream>
#include <sys/stat.h>
#include <termios.h>
#include <sys/select.h>
#include <algorithm>

#include "common.h"

// Constants for different server ports
#define AUTH_PORT 2023
#define PROXY_PORT 2022

// The path for the client-specific SSH key
const std::string CLIENT_KEY_PATH = "~/.ssh/id_rsa_bastion";

// Function to connect to a server given host and port
int connect_to_server(const char *hostname, int port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("[Client] Socket creation failed");
        return -1;
    }

    struct hostent *server = gethostbyname(hostname);
    if (server == NULL)
    {
        std::cerr << "[Client] Error: No such host " << hostname << std::endl;
        return -1;
    }

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        std::cerr << "[Client] Connection failed to " << hostname << ":" << port;
        perror("");
        close(sockfd);
        return -1;
    }
    std::cout << "[Client] Connected to " << hostname << ":" << port << std::endl;
    return sockfd;
}

/**
 * @brief Handles the --register command to exchange SSH keys with the bastion-auth server.
 */
void handle_registration(const char *hostname)
{
    std::cout << "[Client] Starting registration with " << hostname << " on port " << AUTH_PORT << "..." << std::endl;

    // GENERATE KEY:

    // Replace absolute paths with expanded path
    std::string key_path = expand_path(CLIENT_KEY_PATH);
    std::string pub_key_path = key_path + ".pub";

    // Check if key exists, otherwise generate it
    // First remove existing key if it exists
    struct stat buffer;
    if (stat(key_path.c_str(), &buffer) == 0)
    {
        std::cout << "[Client] Existing SSH key found. Removing it..." << std::endl;
        if (std::remove(key_path.c_str()) != 0)
        {
            std::cerr << "[Client] Failed to remove existing SSH key." << std::endl;
            return;
        }
        // Also remove the public key file
        std::string pub_key = key_path + ".pub";
        if (std::remove(pub_key.c_str()) != 0)
        {
            std::cerr << "[Client] Failed to remove existing public SSH key." << std::endl;
            return;
        }
    }

    std::cout << "[Client] Generating a new SSH key at " << key_path << std::endl;
    std::string command = "ssh-keygen -t rsa -b 4096 -f " + key_path + " -N '' -C \"bastion-client-key_" + getCurrentTimestamp() + "\"";

    if (system(command.c_str()) != 0)
    {
        std::cerr << "[Client] Failed to generate SSH key. Please ensure ssh-keygen is installed." << std::endl;
        return;
    }

    // Read the client's public key from the file
    std::ifstream pub_key_file(pub_key_path);
    if (!pub_key_file)
    {
        std::cerr << "[Client] Could not read public key file: " << pub_key_path << std::endl;
        return;
    }
    std::string pub_key_str((std::istreambuf_iterator<char>(pub_key_file)), std::istreambuf_iterator<char>());
    // Connect to the bastion-auth server
    int sock = connect_to_server(hostname, AUTH_PORT);
    if (sock < 0)
        return;

    // HANDSHAKE: Perform handshake to establish a secure channel
    EVP_PKEY *server_static_key = nullptr;
    unsigned char *session_key = perform_client_handshake(sock, hostname, server_static_key);
    if (!session_key)
    {
        std::cerr << "[Client] Failed to perform secure handshake with auth server." << std::endl;
        close(sock);
        EVP_PKEY_free(server_static_key);
        return;
    }
    EVP_PKEY_free(server_static_key);

    // ACTION A: Send the public key over the encrypted channel
    std::vector<unsigned char> pub_key_bytes(pub_key_str.begin(), pub_key_str.end());
    if (!send_encrypted_message(sock, pub_key_bytes, session_key))
    {
        std::cerr << "[Client] Failed to send public key to auth server." << std::endl;
    }
    else
    {
        std::cout << "[Client] Successfully sent public key to the bastion." << std::endl;
    }

    // ACTION B: Receive the bastion's public key in return
    std::vector<unsigned char> bastion_pubkey_bytes = receive_encrypted_message(sock, session_key);
    if (bastion_pubkey_bytes.empty())
    {
        std::cerr << "[Client] Failed to receive bastion's public key." << std::endl;
    }
    else
    {
        std::cout << "[Client] Received bastion's public key." << std::endl;
        std::string bastion_pubkey(bastion_pubkey_bytes.begin(), bastion_pubkey_bytes.end());

        // Add the bastion's key to authorized_keys file
        std::string auth_keys_path = expand_path("~/.ssh/authorized_keys");
        std::ofstream auth_keys(auth_keys_path, std::ios::app);
        if (!auth_keys.is_open())
        {
            std::cerr << "[Client] Failed to open authorized_keys: " << strerror(errno) << std::endl;
        }
        else
        {
            auth_keys << bastion_pubkey;
            if (bastion_pubkey.back() != '\n')
                auth_keys << "\n";
            std::cout << "[Client] Bastion's public key added to " << auth_keys_path << std::endl;
        }

        auth_keys.close();
        chmod(auth_keys_path.c_str(), 0600);
    }

    // Send a success message to the logs
    std::cout << "\nRegistration successful!" << std::endl;
    std::cout << "You can now connect to targets via the bastion using:" << std::endl;
    std::cout << "  " << "./bastion " << hostname << " your_user@target_machine" << std::endl;

    close(sock);
    delete[] session_key;
}

/**
 * @brief Handles the SSH proxy session with the bastion-srv server.
 */
void start_proxy_session(const char *hostname, const char *target)
{
    std::cout << "[Client] Starting proxy session to '" << target << "' via " << hostname << " on port " << PROXY_PORT << "..." << std::endl;

    int sock = connect_to_server(hostname, PROXY_PORT);
    if (sock < 0)
        return;

    // Perform handshake to establish a secure channel
    EVP_PKEY *server_static_key = nullptr;
    unsigned char *session_key = perform_client_handshake(sock, hostname, server_static_key);
    if (!session_key)
    {
        std::cerr << "[Client] Failed to perform secure handshake with proxy server." << std::endl;
        close(sock);
        EVP_PKEY_free(server_static_key);
        return;
    }
    EVP_PKEY_free(server_static_key);

    // PASSWORD AUTHENTICATION
    // --- NEW: AUTHENTICATION STAGE ---
    // 1. Get username and password from user
    std::string username;
    std::cout << "Username: ";
    std::getline(std::cin, username);
    std::string password = get_password_from_stdin(); // Securely get password



    // 2. Send username
    std::vector<unsigned char> username_bytes(username.begin(), username.end());
    if (!send_encrypted_message(sock, username_bytes, session_key))
    {
        std::cerr << "[Client] Failed to send username." << std::endl;
        close(sock);
        delete[] session_key;
        return;
    }

    // 3. Send password
    std::vector<unsigned char> password_bytes(password.begin(), password.end());
    if (!send_encrypted_message(sock, password_bytes, session_key))
    {
        std::cerr << "[Client] Failed to send password." << std::endl;
        close(sock);
        delete[] session_key;
        return;
    }

    // 4. Receive and check authorization status
    std::vector<unsigned char> auth_status_bytes = receive_encrypted_message(sock, session_key);
    if (auth_status_bytes.empty())
    {
        std::cerr << "[Client] Did not receive authorization status from server." << std::endl;
        close(sock);
        delete[] session_key;
        return;
    }
    std::string auth_status(auth_status_bytes.begin(), auth_status_bytes.end());

    if (auth_status != "AUTH_SUCCESS")
    {
        std::cerr << "[Client] Authentication failed. Server response: " << auth_status << std::endl;
        close(sock);
        delete[] session_key;
        return;
    }
    std::cout << "[Client] Authentication successful." << std::endl;
    // --- END OF AUTHENTICATION STAGE ---
    // Send the encrypted target destination
    std::string target_str(target);
    std::vector<unsigned char> target_bytes(target_str.begin(), target_str.end());
    if (!send_encrypted_message(sock, target_bytes, session_key))
    {
        std::cerr << "[Client] Failed to send target information." << std::endl;
        close(sock);
        delete[] session_key;
        return;
    }

    // Set terminal to raw mode
    struct termios old_tio, new_tio;
    tcgetattr(STDIN_FILENO, &old_tio);
    new_tio = old_tio;
    new_tio.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);

    // Proxy data between stdin/stdout and the server
    while (true)
    {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(sock, &fds);

        int activity = select(sock + 1, &fds, nullptr, nullptr, nullptr);
        if (activity < 0)
        {
            perror("[Client] Select failed");
            break;
        }

        // Data from stdin to send to the server
        if (FD_ISSET(STDIN_FILENO, &fds))
        {
            char buffer[4096];
            ssize_t bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (bytes_read <= 0)
                break;
            std::vector<unsigned char> plaintext(buffer, buffer + bytes_read);
            if (!send_encrypted_message(sock, plaintext, session_key))
            {
                std::cerr << "[Client] Failed to send data to server." << std::endl;
                break;
            }
        }

        // Data from server to print to stdout
        if (FD_ISSET(sock, &fds))
        {
            std::vector<unsigned char> decrypted_data = receive_encrypted_message(sock, session_key);
            if (decrypted_data.empty())
            {
                std::cout << "\r\n[Client] Connection closed by server." << std::endl;
                break;
            }
            write(STDOUT_FILENO, decrypted_data.data(), decrypted_data.size());
        }
    }

    // Restore terminal settings and cleanup
    tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
    close(sock);
    delete[] session_key;
}

void print_usage(const char *prog_name)
{
    std::cerr << "Usage: " << prog_name << " <bastion_host> [--register | <user@target_host>]" << std::endl;
    std::cerr << "  --register             : Register this client's new SSH key with the bastion." << std::endl;
    std::cerr << "  <user@target_host>     : Connect to a target host through the bastion proxy." << std::endl;
}

int main(int argc, char *argv[])
{
    // std::cout << getCurrentTimestamp() << " [Client] Starting Bastion Client..." << std::endl;
    if (argc < 3)
    {
        print_usage(argv[0]);
        return 1;
    }

    const char *bastion_host = argv[1];
    const char *command_or_target = argv[2];

    init_openssl();

    if (strcmp(command_or_target, "--register") == 0)
    {
        handle_registration(bastion_host);
    }
    else
    {
        start_proxy_session(bastion_host, command_or_target);
    }

    cleanup_openssl();
    return 0;
}