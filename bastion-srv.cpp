// bastion-srv.cpp
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
#define PORT 2022

void error_exit(const std::string& msg) {
    std::cerr << "[Server Error] " << msg << std::endl;
    exit(EXIT_FAILURE);
}

void handle_client(int client_sock) {
    char buffer[256] = {0};
    int len = read(client_sock, buffer, sizeof(buffer) - 1);
    if (len <= 0) {
        std::cerr << "[Server] Failed to read target\n";
        close(client_sock);
        return;
    }

    std::string target = std::string(buffer, len);
    std::cout << "[Server] Connecting to target: " << target << std::endl;

    pid_t pid = fork();
    if (pid == 0) {
        // Child: Use dup2 to redirect stdin/stdout to socket
        dup2(client_sock, STDIN_FILENO);
        dup2(client_sock, STDOUT_FILENO);
        dup2(client_sock, STDERR_FILENO);
        execlp("ssh", "ssh", "-tt", target.c_str(), nullptr);
        perror("execlp ssh");
        exit(EXIT_FAILURE);
    } else {
        waitpid(pid, nullptr, 0);
        close(client_sock);
    }
}

int main() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error_exit("Socket creation failed");

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        error_exit("Bind failed");

    if (listen(sockfd, 5) < 0)
        error_exit("Listen failed");

    std::cout << "[Server] Listening on port " << PORT << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            std::cerr << "[Server] Accept failed\n";
            continue;
        }

        std::cout << "[Server] Connection accepted\n";
        std::thread(handle_client, client_sock).detach();
    }

    close(sockfd);
    return 0;
}
