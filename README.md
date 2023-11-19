# Secure Communication Server-Client

A simple client-server application for secure communication using OpenSSL. This project demonstrates data transmission with a Message Authentication Code (MAC) for integrity verification.

## Overview

This project consists of a server and client that communicate over a secure channel using OpenSSL. The communication includes sending chunks of data with an attached Message Authentication Code (MAC) to ensure data integrity.

## Features

- Secure communication using OpenSSL
- Message Authentication Code (MAC) for data integrity
- Bandwidth calculation for received data

## Getting Started

### Prerequisites

- C compiler (e.g., GCC)
- OpenSSL library installed

### Installation

1. Clone the repository:

    ```bash
    $ git clone https://git@github.com:DmitriyZhuravlev/CmacBandwidth.git
    $ cd CmacBandwidth
    ```

2. Compile the server and client:

    ```bash
    $ make
    ```

### Usage

1. Start the server:

    ```bash
    $ ./server
    ```

2. In another terminal, start the client:

    ```bash
    $ ./client
    ```

3. The server and client will establish a secure connection, and the client will send chunks of data to the server with MAC for integrity verification.

## Bandwidth Calculation

The project includes bandwidth calculation to measure the speed of data transfer between the server and client.

```c
// Calculate bandwidth in bytes per second
double bandwidth = totalBytesRead / total_time;

printf("Received %zu bytes in %.4f seconds\n", totalBytesRead, total_time);
printf("Total Bandwidth: %.2f bytes/second\n", bandwidth);
printf("Actual Bandwidth (excluding MAC): %.2f bytes/second\n", actual_bandwidth);
