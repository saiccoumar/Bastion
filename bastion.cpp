// bastion.cpp
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <cstring>
#include <sys/wait.h>
#include <termios.h> // For terminal settings

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 2222
// Define CA_CERT_FILE if you want to verify server against a specific CA
// #define CA_CERT_FILE "ca.crt"

// Global SSL context and SSL object for client
SSL_CTX *g_ssl_ctx_client = nullptr;
SSL *g_ssl_client = nullptr;

// Terminal state
struct termios g_old_tio, g_new_tio;
bool g_terminal_set = false;

void print_openssl_errors_client(const std::string& prefix) {
    unsigned long err_code;
    while ((err_code = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        std::cerr << prefix << ": " << err_buf << std::endl;
    }
}

void reset_terminal_and_exit(int status = EXIT_FAILURE) {
    if (g_terminal_set) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_old_tio);
        g_terminal_set = false;
    }
    if (g_ssl_client) {
        // SSL_shutdown(g_ssl_client); // Attempt graceful shutdown
        SSL_free(g_ssl_client); // Frees SSL struct, also closes underlying socket
        g_ssl_client = nullptr;
    }
    if (g_ssl_ctx_client) {
        SSL_CTX_free(g_ssl_ctx_client);
        g_ssl_ctx_client = nullptr;
    }
    ERR_free_strings();
    EVP_cleanup();
    exit(status);
}


void error_exit(const std::string& msg, bool use_perror = false) {
    std::cerr << "[Client Error] " << msg;
    if (use_perror) {
        std::cerr << ": " << strerror(errno);
    }
    std::cerr << std::endl;
    print_openssl_errors_client("[OpenSSL Client Error]");
    reset_terminal_and_exit(EXIT_FAILURE);
}


SSL_CTX* create_client_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    if (!method) {
        error_exit("Unable to create SSL_METHOD instance for client");
    }

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        error_exit("Unable to create SSL_CTX instance for client");
    }

    // Optional: Configure CA path for server verification
    #ifdef CA_CERT_FILE
        if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, nullptr)) {
            error_exit("Failed to load CA certificate: " + std::string(CA_CERT_FILE));
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr); // Enable server certificate verification
    #else
        // WARNING: SSL_VERIFY_NONE is insecure and should not be used in production.
        // It's here for testing with self-signed certificates without a CA.
        std::cout << "[Client Warning] Server certificate verification is disabled (SSL_VERIFY_NONE)." << std::endl;
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    #endif

    return ctx;
}

void set_raw_terminal() {
    if (tcgetattr(STDIN_FILENO, &g_old_tio) != 0) {
        perror("[Client] tcgetattr");
        return; // Continue without raw mode if it fails
    }
    g_new_tio = g_old_tio;
    g_new_tio.c_lflag &= (~ICANON & ~ECHO); // Disable canonical mode and echo
    // You might also want to disable other flags like ISIG for full raw access for SSH
    // g_new_tio.c_iflag &= ~(IXON | IXOFF | ICRNL);
    // g_new_tio.c_oflag &= ~(OPOST);
    // g_new_tio.c_cc[VMIN] = 1;
    // g_new_tio.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &g_new_tio) != 0) {
        perror("[Client] tcsetattr");
    } else {
        g_terminal_set = true;
    }
}

void restore_terminal() {
    if (g_terminal_set) {
        if (tcsetattr(STDIN_FILENO, TCSANOW, &g_old_tio) != 0) {
            perror("[Client] tcsetattr (restore)");
        }
        g_terminal_set = false;
    }
}


int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: bastion <server_ip> <user@target>\n";
        reset_terminal_and_exit(EXIT_FAILURE);
    }

    std::string server_ip = argv[1];
    std::string target = argv[2];

    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms(); // Or OPENSSL_init_ssl(0, NULL);

    g_ssl_ctx_client = create_client_ssl_context();

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) error_exit("Socket creation failed", true);

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        close(sock); // Close socket before exit
        error_exit("Invalid server address or address not supported", true);
    }

    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        error_exit("Could not connect to bastion server (TCP)", true);
    }
    std::cout << "[Client] TCP connection established to " << server_ip << ":" << PORT << std::endl;

    g_ssl_client = SSL_new(g_ssl_ctx_client);
    if (!g_ssl_client) {
        close(sock);
        error_exit("Failed to create SSL structure for client");
    }
    SSL_set_fd(g_ssl_client, sock); // Associates socket with SSL object

    // Optional: Set SNI (Server Name Indication) - good practice if server uses it
    // SSL_set_tlsext_host_name(g_ssl_client, server_ip.c_str()); // Use actual hostname if different from IP

    if (SSL_connect(g_ssl_client) <= 0) {
        // SSL_free will close 'sock' if SSL_set_fd was successful
        // error_exit will call SSL_free
        error_exit("SSL handshake failed with bastion server");
    }
    std::cout << "[Client] SSL handshake successful with bastion server." << std::endl;

    #ifdef CA_CERT_FILE
    if (SSL_get_verify_result(g_ssl_client) != X509_V_OK) {
        std::cerr << "[Client Error] Server certificate verification failed. Error: "
                  << X509_verify_cert_error_string(SSL_get_verify_result(g_ssl_client)) << std::endl;
        error_exit("Server certificate verification failed.");
    }
    std::cout << "[Client] Server certificate verified." << std::endl;
    X509* cert = SSL_get_peer_certificate(g_ssl_client); // Get a copy, needs X509_free
    if (cert) {
        char* subj = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        std::cout << "[Client] Server certificate subject: " << subj << std::endl;
        OPENSSL_free(subj);
        X509_free(cert);
    }
    #endif

    // Send target to bastion server via SSL
    if (SSL_write(g_ssl_client, target.c_str(), target.length()) <= 0) {
        error_exit("Failed to send target to bastion server via SSL");
    }
    std::cout << "[Client] Sent target '" << target << "' to bastion server." << std::endl;

    set_raw_terminal();
    // Ensure terminal is restored on normal or abnormal exit
    atexit(restore_terminal);


    pid_t pid = fork();
    if (pid == -1) {
        error_exit("Fork failed", true);
    }

    if (pid == 0) { // Child process: Read from STDIN, write to SSL socket
        char buf[4096];
        while (true) {
            int n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n < 0) { // Error
                if (errno == EINTR) continue;
                // perror("[Client Child] Read error from STDIN"); // Can be noisy on exit
                break;
            }
            if (n == 0) { // EOF on STDIN (e.g., Ctrl+D)
                // std::cout << "[Client Child] STDIN closed." << std::endl;
                break;
            }
            // Write to SSL socket
            int bytes_written = SSL_write(g_ssl_client, buf, n);
            if (bytes_written <= 0) {
                // int ssl_err = SSL_get_error(g_ssl_client, bytes_written);
                // std::cerr << "[Client Child] SSL_write failed. Code: " << ssl_err << std::endl;
                // print_openssl_errors_client("[OpenSSL Client Child SSL_write]");
                break;
            }
        }
        // Child is done reading from stdin. It should exit.
        // Parent will detect this either by SSL_read failing or by waitpid.
        // No need to explicitly shutdown SSL from child, parent handles the main SSL object.
        exit(0);
    } else { // Parent process: Read from SSL socket, write to STDOUT
        char buf[4096];
        while (true) {
            int n = SSL_read(g_ssl_client, buf, sizeof(buf));
            if (n <= 0) { // Error or connection closed
                // int ssl_err = SSL_get_error(g_ssl_client, n);
                // if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                //     std::cout << "\n[Client Parent] SSL connection closed by server." << std::endl;
                // } else if (ssl_err == SSL_ERROR_SYSCALL && n == 0) { // Often indicates peer closed connection
                //     std::cout << "\n[Client Parent] SSL connection closed (EOF)." << std::endl;
                // } else if (ssl_err == SSL_ERROR_SYSCALL && n == -1 && errno != 0){
                //     // perror("\n[Client Parent] SSL_read SYSCALL error");
                // } else if (n < 0) { // Other SSL errors
                //     // std::cerr << "\n[Client Parent] SSL_read failed. Code: " << ssl_err << std::endl;
                //     // print_openssl_errors_client("[OpenSSL Client Parent SSL_read]");
                // }
                break;
            }
            // Write to STDOUT
            if (write(STDOUT_FILENO, buf, n) < 0) {
                // perror("[Client Parent] Write error to STDOUT");
                break;
            }
        }
        // Loop ended (SSL_read failed or remote closed)
        // std::cout << "\n[Client Parent] SSL->STDOUT loop finished." << std::endl;

        // Ensure child process is terminated and reaped
        kill(pid, SIGTERM); // Send TERM signal to child
        int status;
        waitpid(pid, &status, 0); // Wait for child to exit
        // std::cout << "[Client Parent] Child process terminated." << std::endl;
    }

    // restore_terminal() will be called by atexit hook
    std::cout << "\n[Client] Connection closing." << std::endl;
    reset_terminal_and_exit(EXIT_SUCCESS); // Handles cleanup and exit
    return 0; // Should not be reached due to reset_terminal_and_exit
}