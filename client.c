// client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>

#define PORT 8080

#define ITERATION_NUMBER 1000

#define CMAC_SIZE 16
#define MAX_PACKET_SIZE 1460
#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - CMAC_SIZE)

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


void sendDataWithCMAC(int clientSocket, const char *key, const char *data, size_t dataSize)
{
    char cmacResult[CMAC_SIZE];// = {0x93, 0x9e, 0x81, 0x59, 0xf6, 0xf8, 0xb7, 0xc5, 0x8e, 0x9f, 0x0d, 0xc7, 0x61, 0x53, 0xda, 0xe9};
    char result[MAX_PACKET_SIZE];// = {0};

    for (size_t i = 0; i * MAX_PAYLOAD_SIZE < dataSize; i++)
    {
        // Calculate CMAC for the current chunk
        calculateCMAC(key, data + i * MAX_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE, cmacResult);
        //printf("cmacResult: %s\n", cmacResult);

        // Copy payload to the result buffer
        memcpy(result, data + i * MAX_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE);

        // Copy CMAC to the result buffer
        memcpy(result + MAX_PAYLOAD_SIZE, cmacResult, CMAC_SIZE);

        // Send the chunk (payload + CMAC)
        send(clientSocket, result, MAX_PACKET_SIZE, 0);
        //printf("result: %s\n", result);
    }
}

int main()
{
    int clientSocket;
    struct sockaddr_in serverAddr;

    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(clientSocket, (struct sockaddr * )&serverAddr, sizeof(serverAddr)) == -1)
    {
        perror("Error connecting to server");
        exit(EXIT_FAILURE);
    }

    // Define the key as an array of bytes
    const char key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    
    

    // Generate random data to fill payload + CMAC size of 1460 bytes
    size_t dataSize = MAX_PAYLOAD_SIZE;
    char randomData[MAX_PAYLOAD_SIZE] = {0};
    for (size_t i = 0; i < dataSize; ++i)
    {
        randomData[i] = rand() % 256;  // Fill with random byte values
    }

    for (int i = 0; i < ITERATION_NUMBER; i++)
    {
        sendDataWithCMAC(clientSocket, key, randomData, dataSize);
        //printf("Sent: %d\n", i);
    }

    close(clientSocket);

    return 0;
}
