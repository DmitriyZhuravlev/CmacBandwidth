// server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <time.h>

#define PORT 8080

#define CHANKS_NUMBER 10
#define CMAC_SIZE 16
#define MAX_PACKET_SIZE 1460
#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - CMAC_SIZE)
#define MAX_BUFFER_SIZE (MAX_PACKET_SIZE * CHANKS_NUMBER)

clock_t start_time;

void calculateCMAC(const char *key, const char *data, size_t dataSize, char *cmacResult)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    size_t len;

    ctx = EVP_CIPHER_CTX_new();

    // Debug: Print key
    //printf("Key: ");
    //for (size_t i = 0; i < EVP_CIPHER_key_length(cipher); ++i)
    //{
    //printf("%02x", (unsigned char)key[i]);
    //}
    //printf("\n");

    // Debug: Print input data and size
    //printf("Input Data (Size %zu): ", dataSize);
    //for (size_t i = 0; i < dataSize; ++i)
    //{
    //printf("%02x", (unsigned char)data[i]);
    //}
    //printf("\n");

    EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
    EVP_EncryptUpdate(ctx, cmacResult, &len, data, dataSize);
    EVP_EncryptFinal_ex(ctx, cmacResult, &len);

    // Debug: Print CMAC Result and size
    //printf("CMAC Result (Size %zu): ", len);
    //for (size_t i = 0; i < CMAC_SIZE; ++i)
    //{
    //printf("%02x", (unsigned char)cmacResult[i]);
    //}
    //printf("\n");

    EVP_CIPHER_CTX_free(ctx);
}

int receiveDataWithCMAC(int clientSocket, const char *key, char *buffer, size_t bufferSize)
{
    size_t totalBytesRead = 0;
    char debug[MAX_PACKET_SIZE + 1] = {0};
    static int start = 0;

    while (totalBytesRead < bufferSize)
    {
        // Read the chunk (payload + CMAC)
        ssize_t bytesRead = recv(clientSocket, buffer + totalBytesRead, MAX_PACKET_SIZE, 0);
        //printf("Bytes read: %d \n", bytesRead);
        //ssize_t bytesRead = recv(clientSocket, debug, MAX_PACKET_SIZE, 0);
        //printf("%s \n", buffer + totalBytesRead);
        if (bytesRead <= 0)
        {
            perror("Error receiving data");
            return -1;
        }
        else if (start == 0)
        {
            start = 1;
            start_time = clock();
        }

        char receivedCMAC[CMAC_SIZE];
        calculateCMAC(key, buffer + totalBytesRead, MAX_PAYLOAD_SIZE, receivedCMAC);
        //printf("receivedCMAC: %s \n", receivedCMAC);

        // Verify CMAC
        if (memcmp(receivedCMAC, buffer + totalBytesRead + MAX_PAYLOAD_SIZE, CMAC_SIZE) != 0)
        {
            fprintf(stderr, "CMAC verification failed\n");
            return -1;
        }
        //else
        //{
        //fprintf(stderr, "CMAC verification OK\n");
        //}

        totalBytesRead += bytesRead;

    }

    return totalBytesRead;
}

int main()
{
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrSize = sizeof(clientAddr);

    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr * )&serverAddr, sizeof(serverAddr)) == -1)
    {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    if (listen(serverSocket, 5) == -1)
    {
        perror("Error listening for connections");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    if ((clientSocket = accept(serverSocket, (struct sockaddr * )&clientAddr, &addrSize)) == -1)
    {
        perror("Error accepting connection");
        exit(EXIT_FAILURE);
    }

    // Define the key as an array of bytes
    const char key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

    char receivedData[MAX_BUFFER_SIZE];
    int totalBytesRead = receiveDataWithCMAC(clientSocket, key, receivedData, MAX_BUFFER_SIZE);

    clock_t end_time = clock();
    double total_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    // Calculate bandwidth in bytes per second
    double bandwidth = totalBytesRead / total_time;

    // Calculate actual bandwidth (excluding MAC) in bytes per second
    double actual_bandwidth = (totalBytesRead - (CMAC_SIZE * (totalBytesRead / MAX_PACKET_SIZE))) /
                              total_time;

    printf("Received %zu bytes in %.4f seconds\n", totalBytesRead, total_time);
    printf("Total Bandwidth: %.2f bytes/second\n", bandwidth);
    printf("Actual Bandwidth (excluding MAC): %.2f bytes/second\n", actual_bandwidth);

    close(clientSocket);
    close(serverSocket);

    return 0;
}
