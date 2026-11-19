#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <curl/curl.h>

#define TOR_CONTROL_IP   "127.0.0.1"
#define TOR_CONTROL_PORT 9051
#define TOR_SOCKS_PROXY  "socks5h://127.0.0.1:9050"
#define TOR_PASSWORD     "" // Set if HashedControlPassword is enabled in torrc
#define ROTATE_INTERVAL  10 // Tor enforces a 10-second minimum cooldown on NEWNYM

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    printf("%.*s", (int)total, (char *)ptr);
    return total;
}

int send_tor_command(int sock, const char *cmd, char *response, size_t resp_size) {
    if (send(sock, cmd, strlen(cmd), 0) < 0) {
        perror("send");
        return -1;
    }
    memset(response, 0, resp_size);
    if (recv(sock, response, resp_size - 1, 0) <= 0) {
        perror("recv");
        return -1;
    }
    return 0;
}

void fetch_over_tor(const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize libcurl\n");
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROXY, TOR_SOCKS_PROXY);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);

    // Force new TCP stream
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1L);
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);

    // Enforce strict end-to-end TLS 
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    printf("Exit IP: ");
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Request error: %s\n", curl_easy_strerror(res));
    } else {
        printf("\n");
    }

    curl_easy_cleanup(curl);
}

int main(void) {
    int sock;
    struct sockaddr_in server;
    char response[256];
    char auth_cmd[128];

    curl_global_init(CURL_GLOBAL_ALL);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(TOR_CONTROL_PORT);
    inet_pton(AF_INET, TOR_CONTROL_IP, &server.sin_addr);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Failed to connect to Tor ControlPort (9051)");
        close(sock);
        return 1;
    }

    snprintf(auth_cmd, sizeof(auth_cmd), "AUTHENTICATE \"%s\"\r\n", TOR_PASSWORD);
    if (send_tor_command(sock, auth_cmd, response, sizeof(response)) < 0 ||
        strncmp(response, "250", 3) != 0) {
        fprintf(stderr, "Tor auth failed: %s\n", response);
        close(sock);
        return 1;
    }

    printf("Connected to Tor ControlPort. Rotating circuit every %ds...\n\n", ROTATE_INTERVAL);

    while (1) {
        fetch_over_tor("https://ipify.org");

        if (send_tor_command(sock, "SIGNAL NEWNYM\r\n", response, sizeof(response)) < 0) {
            break;
        }
        printf("SIGNAL NEWNYM -> %s", response);
        sleep(ROTATE_INTERVAL);
    }

    close(sock);
    curl_global_cleanup();
    return 0;
}
