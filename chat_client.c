#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define MAX_USERNAME 32
#define MAX_PASSWORD 32
#define MAX_MESSAGE 256

struct lab9_data {
    char operation;
    char input[256];
    char key[32];
    char result[512];
};

char shared_key[17] = "key123456789abcd"; // Khóa 16 byte cho AES
char des_key[9] = "key12345"; // Khóa 8 byte cho DES
int crypto_fd = -1;
char cipher_algo = '1'; // Mặc định DES, sẽ được cập nhật từ server

// Mã hóa tin nhắn
int encrypt_message(const char *input, char *output) {
    struct lab9_data data;
    memset(&data, 0, sizeof(data));
    data.operation = cipher_algo;
    strncpy(data.input, input, sizeof(data.input) - 1);
    if (cipher_algo == '1') {
        memcpy(data.key, des_key, 8); // Dùng khóa DES
    } else {
        memcpy(data.key, shared_key, 16); // Dùng khóa AES
    }
    data.key[sizeof(data.key) - 1] = '\0';

    printf("Debug: operation=%c, input='%s', key='%s', key_len=%zu\n", 
           data.operation, data.input, data.key, strlen(data.key));

    if (write(crypto_fd, &data, sizeof(data)) != sizeof(data)) {
        fprintf(stderr, "Failed to encrypt message: %s\n", strerror(errno));
        return -1;
    }

    if (read(crypto_fd, &data, sizeof(data)) != sizeof(data)) {
        fprintf(stderr, "Failed to read encrypted message: %s\n", strerror(errno));
        return -1;
    }

    strncpy(output, data.result, sizeof(data.result) - 1);
    return 0;
}

// Giải mã tin nhắn
int decrypt_message(const char *input, char *output) {
    struct lab9_data data;
    memset(&data, 0, sizeof(data));
    data.operation = (cipher_algo == '1') ? '3' : '4';
    strncpy(data.input, input, sizeof(data.input) - 1);
    if (cipher_algo == '1') {
        memcpy(data.key, des_key, 8); // Dùng khóa DES
    } else {
        memcpy(data.key, shared_key, 16); // Dùng khóa AES
    }
    data.key[sizeof(data.key) - 1] = '\0';

    printf("Debug: operation=%c, input='%s', key='%s', key_len=%zu\n", 
           data.operation, data.input, data.key, strlen(data.key));

    if (write(crypto_fd, &data, sizeof(data)) != sizeof(data)) {
        fprintf(stderr, "Failed to decrypt message: %s\n", strerror(errno));
        return -1;
    }

    if (read(crypto_fd, &data, sizeof(data)) != sizeof(data)) {
        fprintf(stderr, "Failed to read decrypted message: %s\n", strerror(errno));
        return -1;
    }

    strncpy(output, data.result, sizeof(data.result) - 1);
    return 0;
}

// Nhận dữ liệu với select để chờ sẵn sàng
int receive_data(int sock, void *buffer, size_t len, int timeout_sec) {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };

    int ret = select(sock + 1, &read_fds, NULL, NULL, &tv);
    if (ret < 0) {
        fprintf(stderr, "Select error: %s\n", strerror(errno));
        return -1;
    }
    if (ret == 0) {
        fprintf(stderr, "Receive timeout\n");
        return -1;
    }

    int bytes_received = recv(sock, buffer, len, 0);
    if (bytes_received < 0) {
        fprintf(stderr, "Failed to receive data: %s\n", strerror(errno));
        return -1;
    }
    if (bytes_received == 0) {
        fprintf(stderr, "Server disconnected\n");
        return -1;
    }
    return bytes_received;
}

// Nhận cấu hình từ server
int receive_config(int sock) {
    char config_msg[1];
    int bytes_received = receive_data(sock, config_msg, sizeof(config_msg), 5);
    if (bytes_received != 1) {
        fprintf(stderr, "Invalid config message length: %d\n", bytes_received);
        return -1;
    }
    cipher_algo = config_msg[0];
    printf("Received cipher algo: %c (%s)\n", cipher_algo, cipher_algo == '1' ? "DES" : "AES");
    return 0;
}

int main() {
    int sock = -1;
    struct sockaddr_in server_addr;

    setbuf(stdin, NULL);

    crypto_fd = open("/dev/lab9_crypto", O_RDWR);
    if (crypto_fd < 0) {
        fprintf(stderr, "Failed to open /dev/lab9_crypto: %s\n", strerror(errno));
        return 1;
    }

    printf("Debug: shared_key='%s', key_len=%zu\n", shared_key, strlen(shared_key));

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Socket creation failed: %s\n", strerror(errno));
        close(crypto_fd);
        return 1;
    }

    // Đặt socket ở chế độ non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        fprintf(stderr, "Failed to set socket non-blocking: %s\n", strerror(errno));
        close(sock);
        close(crypto_fd);
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // Xử lý kết nối non-blocking
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        if (errno != EINPROGRESS) {
            fprintf(stderr, "Connection failed: %s\n", strerror(errno));
            close(sock);
            close(crypto_fd);
            return 1;
        }

        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);
        struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
        int ret = select(sock + 1, NULL, &write_fds, NULL, &timeout);
        if (ret <= 0) {
            fprintf(stderr, "Connect timeout or error: %s\n", ret == 0 ? "Timeout" : strerror(errno));
            close(sock);
            close(crypto_fd);
            return 1;
        }

        int so_error;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
            fprintf(stderr, "Connection failed after select: %s\n", strerror(so_error));
            close(sock);
            close(crypto_fd);
            return 1;
        }
    }
    printf("Connected to server on port %d\n", PORT);

    if (receive_config(sock) < 0) {
        close(sock);
        close(crypto_fd);
        return 1;
    }

    char username[MAX_USERNAME], password[MAX_PASSWORD];
    printf("Enter username: ");
    fflush(stdout);
    if (fgets(username, sizeof(username), stdin) == NULL) {
        fprintf(stderr, "Error reading username\n");
        close(sock);
        close(crypto_fd);
        return 1;
    }
    username[strcspn(username, "\n")] = '\0';
    if (strlen(username) == 0) {
        fprintf(stderr, "Username cannot be empty\n");
        close(sock);
        close(crypto_fd);
        return 1;
    }
    printf("Sent username: '%s'\n", username);

    printf("Enter password: ");
    fflush(stdout);
    if (fgets(password, sizeof(password), stdin) == NULL) {
        fprintf(stderr, "Error reading password\n");
        close(sock);
        close(crypto_fd);
        return 1;
    }
    password[strcspn(password, "\n")] = '\0';
    if (strlen(password) == 0) {
        fprintf(stderr, "Password cannot be empty\n");
        close(sock);
        close(crypto_fd);
        return 1;
    }
    printf("Sent password: '%s'\n", password);

    char username_buf[MAX_USERNAME] = {0};
    char password_buf[MAX_PASSWORD] = {0};
    strncpy(username_buf, username, MAX_USERNAME - 1);
    strncpy(password_buf, password, MAX_PASSWORD - 1);

    if (send(sock, username_buf, MAX_USERNAME, 0) != MAX_USERNAME) {
        fprintf(stderr, "Failed to send username: %s\n", strerror(errno));
        close(sock);
        close(crypto_fd);
        return 1;
    }
    printf("Debug: Sent %d bytes for username\n", MAX_USERNAME);

    if (send(sock, password_buf, MAX_PASSWORD, 0) != MAX_PASSWORD) {
        fprintf(stderr, "Failed to send password: %s\n", strerror(errno));
        close(sock);
        close(crypto_fd);
        return 1;
    }
    printf("Debug: Sent %d bytes for password\n", MAX_PASSWORD);

    int login_result;
    int bytes_received = receive_data(sock, &login_result, sizeof(int), 5);
    if (bytes_received != sizeof(int)) {
        fprintf(stderr, "Invalid login result size: %d\n", bytes_received);
        close(sock);
        close(crypto_fd);
        return 1;
    }
    printf("Received login result: %d\n", login_result);

    char error_msg[MAX_MESSAGE];
    bytes_received = receive_data(sock, error_msg, MAX_MESSAGE, 5);
    if (bytes_received <= 0) {
        fprintf(stderr, "Failed to receive error message: %s\n", bytes_received < 0 ? strerror(errno) : "Server disconnected");
        close(sock);
        close(crypto_fd);
        return 1;
    }
    error_msg[bytes_received < MAX_MESSAGE ? bytes_received - 1 : MAX_MESSAGE - 1] = '\0';
    printf("Received error message: '%s'\n", error_msg);

    if (login_result == 0) {
        printf("Login successful for user %s: %s\n", username, error_msg);
        printf("Start chatting (type 'exit' to quit):\n");
    } else {
        printf("Login failed for user %s: %s\n", username, error_msg);
        close(sock);
        close(crypto_fd);
        return 1;
    }

    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(sock, &read_fds);
        int max_fd = sock;

        struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (activity < 0) {
            fprintf(stderr, "Select error: %s\n", strerror(errno));
            continue;
        }

        // Kiểm tra nhập từ bàn phím
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            char message[MAX_MESSAGE];
            if (fgets(message, sizeof(message), stdin) == NULL) {
                printf("Error reading message\n");
                break;
            }
            message[strcspn(message, "\n")] = '\0';

            if (strcmp(message, "exit") == 0) {
                break;
            }

            char encrypted_msg[512];
            if (encrypt_message(message, encrypted_msg) == 0) {
                int len = strlen(encrypted_msg) + 1;
                if (send(sock, encrypted_msg, len, 0) != len) {
                    fprintf(stderr, "Failed to send message: %s\n", strerror(errno));
                    break;
                }
                printf("Sent encrypted message: %s\n", encrypted_msg);
            } else {
                fprintf(stderr, "Failed to encrypt message\n");
                continue;
            }
        }

        // Kiểm tra phản hồi từ server
        if (FD_ISSET(sock, &read_fds)) {
            char encrypted_reply[512];
            int len = recv(sock, encrypted_reply, sizeof(encrypted_reply), 0);
            if (len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    printf("Debug: No data available from server\n");
                    continue;
                }
                fprintf(stderr, "Failed to receive message: %s\n", strerror(errno));
                break;
            }
            if (len == 0) {
                printf("Server disconnected\n");
                break;
            }
            encrypted_reply[len < sizeof(encrypted_reply) ? len - 1 : sizeof(encrypted_reply) - 1] = '\0';

            char decrypted_reply[256];
            if (decrypt_message(encrypted_reply, decrypted_reply) == 0) {
                printf("Server: %s\n", decrypted_reply);
            } else {
                fprintf(stderr, "Failed to decrypt message\n");
            }
        }
    }

    if (sock >= 0) close(sock);
    if (crypto_fd >= 0) close(crypto_fd);
    printf("Client terminated\n");
    return 0;
}
