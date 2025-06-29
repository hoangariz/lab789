#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define PORT 8080
#define MAX_CLIENTS 10
#define MAX_USERNAME 32
#define MAX_PASSWORD 32
#define MAX_MESSAGE 256

struct lab9_data {
    char operation;
    char input[256];
    char key[32];
    char result[512];
};

struct user {
    char username[MAX_USERNAME];
    char password_hash[65]; // Max 64 for SHA256 hex + null
    char hash_algo; // '5': MD5, '6': SHA1, '7': SHA256
};

char cipher_algo = '2'; // Mặc định AES
char hash_algo = '7';   // Mặc định SHA256
char shared_key[17] = "key123456789abcd"; // Khóa 16 byte cho AES
char des_key[9] = "key12345"; // Khóa 8 byte cho DES
int crypto_fd;

// Băm mật khẩu
int hash_password(const char *password, char *hash, char algo) {
    struct lab9_data data;
    memset(&data, 0, sizeof(data));
    data.operation = algo;
    strncpy(data.input, password, sizeof(data.input) - 1);

    printf("Debug: Hashing password, operation=%c, input='%s'\n", data.operation, data.input);

    if (write(crypto_fd, &data, sizeof(data)) != sizeof(data)) {
        fprintf(stderr, "Failed to write to crypto device: %s\n", strerror(errno));
        return -1;
    }

    if (read(crypto_fd, &data, sizeof(data)) != sizeof(data)) {
        fprintf(stderr, "Failed to read from crypto device: %s\n", strerror(errno));
        return -1;
    }

    strncpy(hash, data.result, 64);
    hash[64] = '\0';
    return 0;
}

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

// Lưu người dùng
int save_user(const char *username, const char *password) {
    char hash[65];
    if (hash_password(password, hash, hash_algo) < 0) {
        fprintf(stderr, "Failed to hash password for user %s\n", username);
        return -1;
    }

    FILE *fp = fopen("users.txt", "a");
    if (!fp) {
        fprintf(stderr, "Failed to open users.txt: %s\n", strerror(errno));
        return -1;
    }

    fprintf(fp, "%s:%s:%c\n", username, hash, hash_algo);
    fclose(fp);
    printf("Saved user %s with hash %s (algo %c)\n", username, hash, hash_algo);
    return 0;
}

// Xác thực người dùng
int verify_user(const char *username, const char *password, char *error_msg) {
    FILE *fp = fopen("users.txt", "r");
    if (!fp) {
        snprintf(error_msg, MAX_MESSAGE, "Server error: Cannot open users.txt (%s)", strerror(errno));
        fprintf(stderr, "%s\n", error_msg);
        return -1;
    }

    char line[256], file_username[MAX_USERNAME], file_hash[65];
    char file_algo;
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        if (sscanf(line, "%31[^:]:%64[^:]:%c", file_username, file_hash, &file_algo) != 3) {
            snprintf(error_msg, MAX_MESSAGE, "Server error: Invalid format in users.txt");
            fprintf(stderr, "%s\n", error_msg);
            fclose(fp);
            return -1;
        }

        if (strcmp(username, file_username) == 0) {
            char input_hash[65];
            if (hash_password(password, input_hash, file_algo) < 0) {
                snprintf(error_msg, MAX_MESSAGE, "Server error: Failed to hash password");
                fprintf(stderr, "%s\n", error_msg);
                fclose(fp);
                return -1;
            }
            fclose(fp);
            if (strcmp(input_hash, file_hash) == 0) {
                snprintf(error_msg, MAX_MESSAGE, "Login successful");
                printf("User %s login successful\n", username);
                return 0;
            } else {
                snprintf(error_msg, MAX_MESSAGE, "Incorrect password");
                printf("User %s login failed: incorrect password\n", username);
                return -2;
            }
        }
    }

    fclose(fp);
    snprintf(error_msg, MAX_MESSAGE, "Username not found");
    printf("User %s login failed: username not found\n", username);
    return -1;
}

// Cấu hình thuật toán
void configure_algorithms() {
    char choice[10];
    printf("\nSelect cipher algorithm:\n1. DES\n2. AES\nChoice: ");
    fflush(stdout);
    if (fgets(choice, sizeof(choice), stdin) == NULL) {
        printf("Error reading cipher choice\n");
        return;
    }
    choice[strcspn(choice, "\n")] = '\0';
    cipher_algo = (choice[0] == '1') ? '1' : '2';

    printf("\nSelect hash algorithm:\n1. MD5\n2. SHA1\n3. SHA256\nChoice: ");
    fflush(stdout);
    if (fgets(choice, sizeof(choice), stdin) == NULL) {
        printf("Error reading hash choice\n");
        return;
    }
    choice[strcspn(choice, "\n")] = '\0';
    hash_algo = (choice[0] == '1') ? '5' : (choice[0] == '2') ? '6' : '7';

    printf("Configured: Cipher=%s, Hash=%s\n", 
           (cipher_algo == '1') ? "DES" : "AES",
           (hash_algo == '5') ? "MD5" : (hash_algo == '6') ? "SHA1" : "SHA256");
}

// Tạo người dùng
void create_user() {
    char username[MAX_USERNAME], password[MAX_PASSWORD];
    printf("Enter username: ");
    fflush(stdout);
    if (fgets(username, sizeof(username), stdin) == NULL) {
        printf("Error reading username\n");
        return;
    }
    username[strcspn(username, "\n")] = '\0';

    printf("Enter password: ");
    fflush(stdout);
    if (fgets(password, sizeof(password), stdin) == NULL) {
        printf("Error reading password\n");
        return;
    }
    password[strcspn(password, "\n")] = '\0';

    if (strlen(username) == 0 || strlen(password) == 0) {
        printf("Username and password cannot be empty\n");
        return;
    }

    if (save_user(username, password) == 0) {
        printf("User %s created successfully\n", username);
    } else {
        printf("Failed to create user %s\n", username);
    }
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_sockets[MAX_CLIENTS];
    char client_users[MAX_CLIENTS][MAX_USERNAME];
    int client_count = 0;

    // Khởi tạo danh sách client_users
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_users[i][0] = '\0';
    }

    // Mở thiết bị crypto
    crypto_fd = open("/dev/lab9_crypto", O_RDWR);
    if (crypto_fd < 0) {
        fprintf(stderr, "Failed to open /dev/lab9_crypto: %s\n", strerror(errno));
        return 1;
    }

    printf("Debug: shared_key='%s', key_len=%zu\n", shared_key, strlen(shared_key));

    // Tạo socket với SO_REUSEADDR
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fprintf(stderr, "Socket creation failed: %s\n", strerror(errno));
        close(crypto_fd);
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        fprintf(stderr, "Setsockopt failed: %s\n", strerror(errno));
        close(server_fd);
        close(crypto_fd);
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Bind failed: %s\n", strerror(errno));
        close(server_fd);
        close(crypto_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        fprintf(stderr, "Listen failed: %s\n", strerror(errno));
        close(server_fd);
        close(crypto_fd);
        return 1;
    }

    printf("Server started on port %d\n", PORT);

    while (1) {
        char choice[10];
        printf("\nMenu:\n1. Configure algorithms\n2. Create user\n3. Start chat\n4. Exit\nChoice: ");
        fflush(stdout);
        if (fgets(choice, sizeof(choice), stdin) == NULL) {
            printf("Error reading menu choice\n");
            continue;
        }
        choice[strcspn(choice, "\n")] = '\0';

        if (choice[0] == '1') {
            configure_algorithms();
        } else if (choice[0] == '2') {
            create_user();
        } else if (choice[0] == '3') {
            printf("Waiting for clients...\n");
            while (client_count < MAX_CLIENTS) {
                // Thêm server_fd vào tập select để chấp nhận client mới
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(server_fd, &read_fds);
                int max_fd = server_fd;
                for (int i = 0; i < client_count; i++) {
                    FD_SET(client_sockets[i], &read_fds);
                    if (client_sockets[i] > max_fd) max_fd = client_sockets[i];
                }

                struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
                int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
                if (activity < 0) {
                    fprintf(stderr, "Select error: %s\n", strerror(errno));
                    continue;
                }

                // Kiểm tra kết nối mới
                if (FD_ISSET(server_fd, &read_fds)) {
                    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
                    if (client_fd < 0) {
                        fprintf(stderr, "Accept failed: %s\n", strerror(errno));
                        continue;
                    }

                    if (send(client_fd, &cipher_algo, 1, 0) <= 0) {
                        printf("Failed to send cipher algo: %s\n", strerror(errno));
                        close(client_fd);
                        continue;
                    }
                    printf("Debug: Sent cipher_algo %c\n", cipher_algo);

                    char username[MAX_USERNAME], password[MAX_PASSWORD];
                    int bytes_received = recv(client_fd, username, MAX_USERNAME, 0);
                    if (bytes_received <= 0) {
                        printf("Failed to receive username from client, bytes: %d (%s)\n", bytes_received, strerror(errno));
                        close(client_fd);
                        continue;
                    }
                    username[bytes_received < MAX_USERNAME ? bytes_received - 1 : MAX_USERNAME - 1] = '\0';
                    printf("Received username: '%s' (length: %d)\n", username, bytes_received);

                    bytes_received = recv(client_fd, password, MAX_PASSWORD, 0);
                    if (bytes_received <= 0) {
                        printf("Failed to receive password from client, bytes: %d (%s)\n", bytes_received, strerror(errno));
                        close(client_fd);
                        continue;
                    }
                    password[bytes_received < MAX_PASSWORD ? bytes_received - 1 : MAX_PASSWORD - 1] = '\0';
                    printf("Received password: '%s' (length: %d)\n", password, bytes_received);

                    int user_exists = 0;
                    for (int i = 0; i < client_count; i++) {
                        if (client_users[i][0] == '\0') continue;
                        if (strcmp(client_users[i], username) == 0) {
                            user_exists = 1;
                            break;
                        }
                    }

                    char error_msg[MAX_MESSAGE];
                    int login_result = verify_user(username, password, error_msg);
                    printf("Login result for %s: %d, Message: %s\n", username, login_result, error_msg);

                    if (user_exists) {
                        snprintf(error_msg, MAX_MESSAGE, "Username %s already logged in", username);
                        login_result = -3;
                        printf("User %s rejected: already logged in\n", username);
                    }

                    if (send(client_fd, &login_result, sizeof(int), 0) <= 0) {
                        printf("Failed to send login result to client %s: %s\n", username, strerror(errno));
                        close(client_fd);
                        continue;
                    }
                    printf("Debug: Sent login_result %d\n", login_result);

                    if (send(client_fd, error_msg, strlen(error_msg) + 1, 0) <= 0) {
                        printf("Failed to send error message to client %s: %s\n", username, strerror(errno));
                        close(client_fd);
                        continue;
                    }
                    printf("Debug: Sent error_msg '%s'\n", error_msg);

                    if (login_result == 0) {
                        client_sockets[client_count] = client_fd;
                        strncpy(client_users[client_count], username, MAX_USERNAME - 1);
                        client_users[client_count][MAX_USERNAME - 1] = '\0';
                        client_count++;
                        printf("User %s connected (total clients: %d)\n", username, client_count);
                    } else {
                        printf("Closing connection for %s due to login failure: %s\n", username, error_msg);
                        close(client_fd);
                    }
                }

                // Kiểm tra tin nhắn từ client
                for (int i = 0; i < client_count; i++) {
                    if (FD_ISSET(client_sockets[i], &read_fds)) {
                        char encrypted_msg[512];
                        int len = recv(client_sockets[i], encrypted_msg, sizeof(encrypted_msg), 0);
                        if (len <= 0) {
                            printf("User %s disconnected (recv returned %d: %s)\n", 
                                   client_users[i], len, strerror(errno));
                            close(client_sockets[i]);
                            for (int j = i; j < client_count - 1; j++) {
                                client_sockets[j] = client_sockets[j + 1];
                                strcpy(client_users[j], client_users[j + 1]);
                            }
                            client_count--;
                            continue;
                        }

                        encrypted_msg[len < sizeof(encrypted_msg) ? len : sizeof(encrypted_msg) - 1] = '\0';
                        printf("Debug: Received encrypted message from %s: %s (len=%d)\n", 
                               client_users[i], encrypted_msg, len);

                        char decrypted_msg[256];
                        if (decrypt_message(encrypted_msg, decrypted_msg) == 0) {
                            printf("Received from %s: %s\n", client_users[i], decrypted_msg);
                            char broadcast_msg[512];
                            snprintf(broadcast_msg, sizeof(broadcast_msg), "%s: %s", client_users[i], decrypted_msg);

                            char encrypted_broadcast[512];
                            if (encrypt_message(broadcast_msg, encrypted_broadcast) == 0) {
                                for (int j = 0; j < client_count; j++) {
                                    if (j != i) {
                                        if (send(client_sockets[j], encrypted_broadcast, 
                                                 strlen(encrypted_broadcast) + 1, 0) <= 0) {
                                            printf("Failed to broadcast to client %s: %s\n", 
                                                   client_users[j], strerror(errno));
                                        }
                                    }
                                }
                            } else {
                                printf("Failed to encrypt broadcast message for %s\n", client_users[i]);
                            }
                        } else {
                            printf("Failed to decrypt message from %s\n", client_users[i]);
                        }
                    }
                }
            }
        } else if (choice[0] == '4') {
            break;
        } else {
            printf("Invalid choice\n");
        }
    }

    for (int i = 0; i < client_count; i++) {
        close(client_sockets[i]);
    }
    close(server_fd);
    close(crypto_fd);
    printf("Server terminated\n");
    return 0;
}
