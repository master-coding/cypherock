## Table of Contents
- [Installation](#installation)
- [Possible Problems while running](#possible-problems-while-running)
- [Code Explanation](#code-explanation)
- [Learnings](#learnings)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/username/repository.git
   ```
2. Run the make file to build the code
   ```bash
   make
   ```
3. Open the executable file
    ```bash
    ./cypherock
    ```

## Possible Problems While Running

- If it gives an error like this, or any library not found, then make sure to correctly install and link it, possible reason might be it is not in default library search path
    ```bash
    ld: library 'ssl' not found
    ```
- Make sure to ensure your gcc command includes the correct library path.
- Replace project_root with the location where the file is saved. 
    ```bash
    gcc -I<project_root>/include \
        -I<project_root>/libs/trezor-firmware/crypto \
        -I<project_root>/vendor/secp256k1-zkp/include \
        -I<project_root>/libs/openssl/include \
        -L<project_root>/vendor/secp256k1-zkp/.libs \
        -L<project_root>/libs/trezor-firmware/crypto \
        -L/usr/local/opt/openssl@3/lib \
        -L<project_root>/libs/openssl \
        <project_root>/src/cypherock.c \
        -o <project_root>/cypherock \
        -lsecp256k1 -ltrezor-crypto -lssl -lcrypto
    ```

## Code Explanation
The code implements a **Correlated Oblivious Transfer** (COT) protocol as part of assignment.

- First I have included some standard header files and `ecdsa.h`, `secp256k1.h`, and `sha2.h` which are part of the Trezor library, which provides elliptic curve operations.
- Defining a Byte length of 32 bytes as part of assignment
-  This function performs the XOR operation between two byte arrays a and b. This is used for providing encryption.
```c
void xor_bytes([params])
``` 
- It is used for generating random bytes. It uses `dev/urandom`. It is used for ensuring randomness
```c
void generate_random_bytes([params])
```
- This function calculates the SHA-256 hash of the given data.
```c
void compute_sha256_commitment([params])
```
- This function multiplies two numbers `a` and `b` under a finite field, which is often used in elliptic curve cryptography, as given in assigment.
```c
void mod_multiply([params])
```
- It creates two shares that
    1. Independently look random
    1. Can be combined to reveal the product
    1. Ensures neither party knows full information
```c
void correlated_oblivious_transfer([params])
```
- It Verifies that shares can be combined to reproduce original product
```c
int verify_correlated_oblivious_transfer([params])
```

### Preview of the code
![](./preview.png)

## Learnings