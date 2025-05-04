// bastion.cpp
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <cstring>
#include <sys/wait.h>

#define PORT 2022

void error_exit(const std::string& msg) {
    std::cerr << "[Client Error] " << msg << std::endl;
    exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: bastion <server_ip> <user@target>\n";
        return EXIT_FAILURE;
    }

    std::string server_ip = argv[1];
    std::string target = argv[2];

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) error_exit("Socket creation failed");

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0)
        error_exit("Invalid server address");

    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        error_exit("Could not connect to bastion server");

    // Send target
    write(sock, target.c_str(), target.size());

    // Fork for bidirectional I/O
    pid_t pid = fork();
    if (pid == 0) {
        char buf[256];
        while (true) {
            int n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) break;
            write(sock, buf, n);
        }
        exit(0);
    } else {
        char buf[256];
        while (true) {
            int n = read(sock, buf, sizeof(buf));
            if (n <= 0) break;
            write(STDOUT_FILENO, buf, n);
        }
        waitpid(pid, nullptr, 0);
    }

    close(sock);
    return 0;
}
