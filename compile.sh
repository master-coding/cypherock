#!/bin/bash

# Compiler
CC=gcc

# Project Paths
PROJECT_ROOT=~/Desktop/Development/cypherock
INCLUDE_PATHS="-I${PROJECT_ROOT}/include \
               -I${PROJECT_ROOT}/libs/trezor-firmware/crypto \
               -I${PROJECT_ROOT}/libs/secp256k1/include \
               -I${PROJECT_ROOT}/libs/openssl/include"

LIBRARY_PATHS="-L${PROJECT_ROOT}/libs/secp256k1/src \
               -L${PROJECT_ROOT}/libs/trezor-firmware/crypto \
               -L${PROJECT_ROOT}/libs/openssl"

# Libraries to link
LIBS="-lsecp256k1 \
      -ltrezor-crypto \
      -lssl \
      -lcrypto"

# Compilation
$CC $INCLUDE_PATHS $LIBRARY_PATHS \
    ${PROJECT_ROOT}/src/cypherock.c \
    -o ${PROJECT_ROOT}/cypherock $LIBS

# Make executable
chmod +x ${PROJECT_ROOT}/cypherock