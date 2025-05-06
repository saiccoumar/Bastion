
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <sys/wait.h>
#include <sys/select.h> 
#include <thread>
#include <vector>
#include <fcntl.h>     
#include <arpa/inet.h> 

#include <openssl/ssl.h>
#include <openssl/err.h>


#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>


#define PORT 2222
#define CERT_FILE "server.crt" 
#define KEY_FILE "server.key"  
#define PROXY_BUF_SIZE 4096


SSL_CTX *g_ssl_ctx = nullptr;

void print_openssl_errors(const std::string& prefix) {
    unsigned long err_code;
    while ((err_code = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        std::cerr << prefix << ": " << err_buf << std::endl;
    }
}



[[noreturn]] void error_exit(const std::string& msg, bool use_perror = false) {
    std::cerr << "[Server Error] " << msg;
    if (use_perror) {
        std::cerr << ": " << strerror(errno);
    }
    std::cerr << std::endl;
    print_openssl_errors("[OpenSSL Server Error]");
    if (g_ssl_ctx) { 
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = nullptr;
    }
    ERR_free_strings();
    EVP_cleanup();
    exit(EXIT_FAILURE);
}

SSL_CTX* create_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    if (!method) {
        error_exit("Unable to create SSL_METHOD instance");
    }

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        error_exit("Unable to create SSL_CTX instance");
    }

    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        error_exit("Failed to load server certificate: " + std::string(CERT_FILE));
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        error_exit("Failed to load server private key: " + std::string(KEY_FILE));
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        error_exit("Private key does not match the public certificate");
    }
    return ctx;
}


void do_proxy(SSL* ssl, int ssh_stdin_pipe_write_fd, int ssh_stdout_pipe_read_fd, pid_t ssh_pid) {
    fd_set current_read_fds, current_write_fds;
    char buffer[PROXY_BUF_SIZE];
    int ssl_fd = SSL_get_fd(ssl);

    
    std::vector<char> ssl_to_ssh_pending_data;
    std::vector<char> ssh_to_ssl_pending_data;

    bool ssl_read_active = true;      
    bool ssh_pipe_read_active = true; 
    bool ssl_needs_write_for_op = false; 

    std::cout << "[Proxy " << getpid() << "] Starting select loop. SSL_FD=" << ssl_fd 
              << ", SSH_out_FD=" << ssh_stdout_pipe_read_fd 
              << ", SSH_in_FD=" << ssh_stdin_pipe_write_fd << std::endl;

    while (ssl_read_active || ssh_pipe_read_active || !ssl_to_ssh_pending_data.empty() || !ssh_to_ssl_pending_data.empty()) {
        FD_ZERO(&current_read_fds);
        FD_ZERO(&current_write_fds);
        int max_fd = 0;

        
        if (ssl_read_active && ssl_to_ssh_pending_data.empty()) {
            FD_SET(ssl_fd, &current_read_fds);
            if (ssl_fd > max_fd) max_fd = ssl_fd;
        }
        
        if (ssh_pipe_read_active && ssh_to_ssl_pending_data.empty()) {
            FD_SET(ssh_stdout_pipe_read_fd, &current_read_fds);
            if (ssh_stdout_pipe_read_fd > max_fd) max_fd = ssh_stdout_pipe_read_fd;
        }

        
        if (!ssl_to_ssh_pending_data.empty() && ssh_stdin_pipe_write_fd != -1) {
            FD_SET(ssh_stdin_pipe_write_fd, &current_write_fds);
            if (ssh_stdin_pipe_write_fd > max_fd) max_fd = ssh_stdin_pipe_write_fd;
        }
        
        if (!ssh_to_ssl_pending_data.empty() || ssl_needs_write_for_op) {
            FD_SET(ssl_fd, &current_write_fds);
            if (ssl_fd > max_fd) max_fd = ssl_fd;
        }
        
        if (max_fd == 0 && !(ssl_read_active || ssh_pipe_read_active || !ssl_to_ssh_pending_data.empty() || !ssh_to_ssl_pending_data.empty())) {
            
            
            
             std::cout << "[Proxy " << getpid() << "] max_fd is 0, checking exit conditions." << std::endl;
            break;
        }


        int activity = select(max_fd + 1, &current_read_fds, &current_write_fds, nullptr, nullptr);

        if (activity < 0) {
            if (errno == EINTR) continue;
            perror("[Proxy] select failed");
            break; 
        }
        if (activity == 0) continue; 

        ssl_needs_write_for_op = false; 

        
        if (ssl_read_active && FD_ISSET(ssl_fd, &current_read_fds)) {
            int bytes = SSL_read(ssl, buffer, PROXY_BUF_SIZE);
            if (bytes > 0) {
                ssl_to_ssh_pending_data.insert(ssl_to_ssh_pending_data.end(), buffer, buffer + bytes);
            } else if (bytes == 0) { 
                std::cout << "[Proxy " << getpid() << "] SSL_read: EOF (client closed connection)." << std::endl;
                ssl_read_active = false; 
                
            } else { 
                int ssl_err = SSL_get_error(ssl, bytes);
                if (ssl_err == SSL_ERROR_WANT_READ) {  }
                else if (ssl_err == SSL_ERROR_WANT_WRITE) { ssl_needs_write_for_op = true; }
                else {
                    std::cerr << "[Proxy " << getpid() << "] SSL_read failed. Error: " << ssl_err << std::endl;
                    print_openssl_errors("[Proxy OpenSSL SSL_read]");
                    ssl_read_active = false;
                }
            }
        }

        
        if (ssh_pipe_read_active && FD_ISSET(ssh_stdout_pipe_read_fd, &current_read_fds)) {
            int bytes = read(ssh_stdout_pipe_read_fd, buffer, PROXY_BUF_SIZE);
            if (bytes > 0) {
                ssh_to_ssl_pending_data.insert(ssh_to_ssl_pending_data.end(), buffer, buffer + bytes);
            } else if (bytes == 0) { 
                std::cout << "[Proxy " << getpid() << "] Read from SSH pipe: EOF (SSH process closed pipe)." << std::endl;
                ssh_pipe_read_active = false; 
                close(ssh_stdout_pipe_read_fd); 
                ssh_stdout_pipe_read_fd = -1;   
            } else { 
                if (errno == EINTR || errno == EAGAIN) {  }
                else {
                    std::cerr << "[Proxy " << getpid() << "] read from ssh_stdout_pipe failed: "<< strerror(errno) << std::endl;
                    ssh_pipe_read_active = false;
                    if(ssh_stdout_pipe_read_fd != -1) close(ssh_stdout_pipe_read_fd);
                    ssh_stdout_pipe_read_fd = -1;
                }
            }
        }

        
        if (ssh_stdin_pipe_write_fd != -1 && !ssl_to_ssh_pending_data.empty() && FD_ISSET(ssh_stdin_pipe_write_fd, &current_write_fds)) {
            int bytes = write(ssh_stdin_pipe_write_fd, ssl_to_ssh_pending_data.data(), ssl_to_ssh_pending_data.size());
            if (bytes > 0) {
                ssl_to_ssh_pending_data.erase(ssl_to_ssh_pending_data.begin(), ssl_to_ssh_pending_data.begin() + bytes);
            } else if (bytes < 0) { 
                 if (errno == EINTR || errno == EAGAIN) {  }
                 else if (errno == EPIPE) { 
                    std::cerr << "[Proxy " << getpid() << "] Write to ssh_stdin_pipe failed (EPIPE)." << std::endl;
                    ssl_read_active = false; 
                    ssl_to_ssh_pending_data.clear(); 
                    close(ssh_stdin_pipe_write_fd);
                    ssh_stdin_pipe_write_fd = -1;
                 } else {
                    std::cerr << "[Proxy " << getpid() << "] write to ssh_stdin_pipe failed" << std::endl;
                    
                    close(ssh_stdin_pipe_write_fd); 
                    ssh_stdin_pipe_write_fd = -1;
                 }
            }
        }
        
        if (!ssl_read_active && ssl_to_ssh_pending_data.empty() && ssh_stdin_pipe_write_fd != -1) {
            std::cout << "[Proxy " << getpid() << "] Client side done, closing pipe to SSH stdin." << std::endl;
            close(ssh_stdin_pipe_write_fd);
            ssh_stdin_pipe_write_fd = -1;
        }


        
        if ((!ssh_to_ssl_pending_data.empty() || ssl_needs_write_for_op) && FD_ISSET(ssl_fd, &current_write_fds)) {
            if (!ssh_to_ssl_pending_data.empty()) {
                int bytes = SSL_write(ssl, ssh_to_ssl_pending_data.data(), ssh_to_ssl_pending_data.size());
                if (bytes > 0) {
                    ssh_to_ssl_pending_data.erase(ssh_to_ssl_pending_data.begin(), ssh_to_ssl_pending_data.begin() + bytes);
                } else { 
                    int ssl_err = SSL_get_error(ssl, bytes);
                    if (ssl_err == SSL_ERROR_WANT_WRITE) { ssl_needs_write_for_op = true; }
                    else if (ssl_err == SSL_ERROR_WANT_READ) {  }
                    else {
                        std::cerr << "[Proxy " << getpid() << "] SSL_write failed. Error: " << ssl_err << std::endl;
                        print_openssl_errors("[Proxy OpenSSL SSL_write]");
                        ssh_pipe_read_active = false; 
                        ssh_to_ssl_pending_data.clear(); 
                    }
                }
            } else if (ssl_needs_write_for_op) {
                
                
                
                
            }
        }
    } 

    std::cout << "[Proxy " << getpid() << "] Exited select loop." << std::endl;

    
    if (ssh_stdin_pipe_write_fd != -1) close(ssh_stdin_pipe_write_fd);
    if (ssh_stdout_pipe_read_fd != -1) close(ssh_stdout_pipe_read_fd);

    
    std::cout << "[Proxy " << getpid() << "] Waiting for SSH child process " << ssh_pid << " to terminate." << std::endl;
    int status;
    if (waitpid(ssh_pid, &status, WNOHANG) == 0) { 
        kill(ssh_pid, SIGTERM); 
        sleep(1); 
        if (waitpid(ssh_pid, &status, WNOHANG) == 0) { 
            std::cout << "[Proxy " << getpid() << "] SSH child " << ssh_pid << " unresponsive, sending SIGKILL." << std::endl;
            kill(ssh_pid, SIGKILL); 
        }
    }
    waitpid(ssh_pid, &status, 0); 
    if (WIFEXITED(status)) {
        std::cout << "[Proxy " << getpid() << "] SSH child " << ssh_pid << " exited with status " << WEXITSTATUS(status) << "." << std::endl;
    } else if (WIFSIGNALED(status)) {
        std::cout << "[Proxy " << getpid() << "] SSH child " << ssh_pid << " killed by signal " << WTERMSIG(status) << "." << std::endl;
    }
    std::cout << "[Proxy " << getpid() << "] SSH child reaped." << std::endl;
}


void handle_client(int client_sock_tcp) {
    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) {
        std::cerr << "[Server MainThr] Failed to create SSL structure." << std::endl;
        print_openssl_errors("[OpenSSL Server Error]");
        close(client_sock_tcp);
        return;
    }

    SSL_set_fd(ssl, client_sock_tcp);

    if (SSL_accept(ssl) <= 0) {
        std::cerr << "[Server MainThr] SSL handshake failed." << std::endl;
        print_openssl_errors("[OpenSSL Server Error]");
        SSL_free(ssl);
        return;
    }
    std::cout << "[Server MainThr " << std::this_thread::get_id() << "] SSL handshake successful with client." << std::endl;

    char target_buffer[256] = {0};
    int len = SSL_read(ssl, target_buffer, sizeof(target_buffer) - 1);
    if (len <= 0) {
        int ssl_error = SSL_get_error(ssl, len);
        std::cerr << "[Server MainThr] Failed to read target. SSL_read returned " << len 
                  << ". SSL error: " << ssl_error << std::endl;
        print_openssl_errors("[OpenSSL Server Error]");
        SSL_shutdown(ssl); SSL_free(ssl); return;
    }
    std::string target(target_buffer, len);
    std::cout << "[Server MainThr " << std::this_thread::get_id() << "] Received target via SSL: " << target << std::endl;

    int client_to_ssh_pipe[2]; 
    int ssh_to_client_pipe[2]; 

    if (pipe(client_to_ssh_pipe) == -1 || pipe(ssh_to_client_pipe) == -1) {
        perror("[Server MainThr] pipe creation failed");
        SSL_shutdown(ssl); SSL_free(ssl); return;
    }

    pid_t proxy_child_pid = fork(); 

    if (proxy_child_pid == -1) {
        perror("[Server MainThr] fork for proxy_child failed");
        close(client_to_ssh_pipe[0]); close(client_to_ssh_pipe[1]);
        close(ssh_to_client_pipe[0]); close(ssh_to_client_pipe[1]);
        SSL_shutdown(ssl); SSL_free(ssl); return;
    }

    if (proxy_child_pid == 0) { 
        std::cout << "[Proxy Child " << getpid() << "] Created." << std::endl;

        
        
        

        pid_t ssh_grandchild_pid = fork(); 

        if (ssh_grandchild_pid == -1) {
            std::cerr << "[Proxy Child " << getpid() << "] fork for ssh_grandchild failed: " << strerror(errno) << std::endl;
            
            close(client_to_ssh_pipe[0]); close(client_to_ssh_pipe[1]);
            close(ssh_to_client_pipe[0]); close(ssh_to_client_pipe[1]);
            exit(EXIT_FAILURE);
        }

        if (ssh_grandchild_pid == 0) { 
            std::cout << "[SSH Grandchild " << getpid() << "] Created. Target: " << target << std::endl;

            
            close(client_to_ssh_pipe[1]); 
            close(ssh_to_client_pipe[0]); 

            
            if (dup2(client_to_ssh_pipe[0], STDIN_FILENO) == -1) {
                perror("[SSH Grandchild] dup2 stdin failed"); exit(EXIT_FAILURE);
            }
            if (dup2(ssh_to_client_pipe[1], STDOUT_FILENO) == -1) {
                perror("[SSH Grandchild] dup2 stdout failed"); exit(EXIT_FAILURE);
            }
            if (dup2(ssh_to_client_pipe[1], STDERR_FILENO) == -1) { 
                perror("[SSH Grandchild] dup2 stderr failed"); exit(EXIT_FAILURE);
            }

            
            close(client_to_ssh_pipe[0]);
            close(ssh_to_client_pipe[1]);

            
            
            close(SSL_get_fd(ssl)); 

            execlp("ssh", "ssh", "-tt", target.c_str(), (char *)nullptr);

            
            std::cerr << "[SSH Grandchild " << getpid() << "] execlp ssh failed: " << strerror(errno) << std::endl;
            exit(EXIT_FAILURE); 

        } else { 
            
            close(client_to_ssh_pipe[0]); 
            close(ssh_to_client_pipe[1]); 

            
            do_proxy(ssl, client_to_ssh_pipe[1], ssh_to_client_pipe[0], ssh_grandchild_pid);

            
            

            std::cout << "[Proxy Child " << getpid() << "] Proxy finished. Exiting." << std::endl;
            
            
            exit(EXIT_SUCCESS); 
        }
    } 

    else { 
        
        
        close(client_to_ssh_pipe[0]); close(client_to_ssh_pipe[1]);
        close(ssh_to_client_pipe[0]); close(ssh_to_client_pipe[1]);

        std::cout << "[Server MainThr " << std::this_thread::get_id() << "] Proxy child " << proxy_child_pid << " launched. Waiting..." << std::endl;
        int status;
        waitpid(proxy_child_pid, &status, 0);
        
        if (WIFEXITED(status)) {
            std::cout << "[Server MainThr " << std::this_thread::get_id() << "] Proxy child " << proxy_child_pid << " exited status " << WEXITSTATUS(status) << "." << std::endl;
        } else if (WIFSIGNALED(status)) {
            std::cout << "[Server MainThr " << std::this_thread::get_id() << "] Proxy child " << proxy_child_pid << " killed by signal " << WTERMSIG(status) << "." << std::endl;
        }

        std::cout << "[Server MainThr " << std::this_thread::get_id() << "] Shutting down SSL." << std::endl;
        int shut_ret = SSL_shutdown(ssl);
        if (shut_ret == 0) { SSL_shutdown(ssl); } 
        
        SSL_free(ssl); 
        std::cout << "[Server MainThr " << std::this_thread::get_id() << "] Client handling complete." << std::endl;
    }
}

void sigchld_handler(int signum) {
    (void)signum; 
    while (waitpid(-1, NULL, WNOHANG) > 0); 
}

int main() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms(); 

    g_ssl_ctx = create_ssl_context(); 

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, 0) == -1) {
        error_exit("sigaction for SIGCHLD failed", true);
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error_exit("Socket creation failed", true);

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(sockfd); error_exit("setsockopt SO_REUSEADDR failed", true);
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockfd); error_exit("Bind failed", true);
    }

    if (listen(sockfd, 20) < 0) { 
        close(sockfd); error_exit("Listen failed", true);
    }

    std::cout << "[Server Main] Listening on port " << PORT << " (TLS enabled, with proxying)" << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_sock_tcp = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock_tcp < 0) {
            if (errno == EINTR) continue; 
            perror("[Server Main] Accept failed");
            continue;
        }

        char client_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, INET_ADDRSTRLEN);
        std::cout << "[Server Main] TCP Connection accepted from " << client_ip_str << ":" << ntohs(client_addr.sin_port) << std::endl;

        std::thread(handle_client, client_sock_tcp).detach();
    }

    close(sockfd);
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
    ERR_free_strings();
    EVP_cleanup();
    std::cout << "[Server Main] Shutting down." << std::endl;
    return 0;
}