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

#define ITERATION_NUMBER 1000000
#define CHANKS_NUMBER 1
#define CMAC_SIZE 16
#define MAX_PACKET_SIZE 1460
#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - CMAC_SIZE)
#define MAX_BUFFER_SIZE (MAX_PACKET_SIZE * CHANKS_NUMBER)

clock_t start_time;

void printBytes(unsigned char *buf, size_t len) {
    for(int i=0; i<len; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

void calculateCMAC(const char *key, const char *data, size_t dataSize, char *cmacResult)
{
    size_t len;
    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key, CMAC_SIZE, EVP_aes_128_cbc(), NULL);

    CMAC_Update(ctx, data, dataSize);
    CMAC_Final(ctx, cmacResult, &len);

    //printBytes(cmacResult, len);

    CMAC_CTX_free(ctx);
}

int receiveDataWithCMAC(int clientSocket, const char *key) //, char *buffer, size_t bufferSize)
{
    size_t totalBytesRead = 0;
    static int start = 0;
    char buffer[MAX_PACKET_SIZE];

    while (totalBytesRead < CHANKS_NUMBER * MAX_PACKET_SIZE)
    {
        // Read the chunk (payload + CMAC)
        ssize_t bytesRead = 0;
        ssize_t bufSize = MAX_PACKET_SIZE;
        ssize_t partialRead = 0;
        while (bytesRead < MAX_PACKET_SIZE)
        {
            partialRead = recv(clientSocket, buffer + bytesRead, bufSize, 0);
            //if (partialRead < MAX_PACKET_SIZE)
            //{
                //printf("Read: %d\n", partialRead);
                //printf("Read Total: %d\n", totalBytesRead);
            //}
            bytesRead += partialRead;
            bufSize = MAX_PACKET_SIZE - bytesRead;
            if (partialRead <= 0)
            {
                perror("Error receiving data");
                return -1;
                //continue;
            }
        }

        if (start == 0)
        {
            start = 1;
            start_time = clock();
        }

        char receivedCMAC[CMAC_SIZE];
        calculateCMAC(key, buffer, MAX_PAYLOAD_SIZE, receivedCMAC);
        //printf("receivedCMAC: %s \n", receivedCMAC);

        // Verify CMAC
        if (memcmp(receivedCMAC, buffer + MAX_PAYLOAD_SIZE, CMAC_SIZE) != 0)
        {
            fprintf(stderr, "CMAC verification failed\n");
            //return -1;
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

    int totalBytesRead = 0;
    for (int i = 0; i < ITERATION_NUMBER; i++)
    {
        totalBytesRead += receiveDataWithCMAC(clientSocket, key); //, receivedData, MAX_BUFFER_SIZE);
    }

    clock_t end_time = clock();
    double total_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    // Calculate bandwidth in bytes per second
    double bandwidth = totalBytesRead / total_time;

    // Calculate actual bandwidth (excluding MAC) in megabytes per second
    double actual_bandwidth_MB = ((totalBytesRead - (CMAC_SIZE * (totalBytesRead / MAX_PACKET_SIZE))) /
                                  total_time) / (1024 * 1024);

    printf("Received %.2f MB in %.4f seconds\n", (double) totalBytesRead / (1024 * 1024), total_time);
    printf("Total Bandwidth: %.2f MB/second\n", bandwidth / (1024 * 1024));
    printf("Actual Bandwidth (excluding MAC): %.2f MB/second\n", actual_bandwidth_MB);

    close(clientSocket);
    close(serverSocket);

    return 0;
}
