# Compiler
CC = gcc

# Project Paths
PROJECT_ROOT = $(HOME)/Desktop/Development/cypherock
INCLUDE_PATHS = -I$(PROJECT_ROOT)/include \
                -I$(PROJECT_ROOT)/libs/trezor-firmware/crypto \
                -I$(PROJECT_ROOT)/vendor/secp256k1-zkp/include \
                -I$(PROJECT_ROOT)/libs/openssl/include

LIBRARY_PATHS = -L$(PROJECT_ROOT)/vendor/secp256k1-zkp/.libs \
                -L$(PROJECT_ROOT)/libs/trezor-firmware/crypto \
                -L$(PROJECT_ROOT)/libs/openssl

# Libraries to link
LIBS = -lsecp256k1 \
       -ltrezor-crypto \
       -lssl \
       -lcrypto

# Source and Target
SRC = $(PROJECT_ROOT)/src/cypherock.c
TARGET = $(PROJECT_ROOT)/cypherock

# Default target
all: $(TARGET)

# Build the target executable
$(TARGET): $(SRC)
	$(CC) $(INCLUDE_PATHS) $(LIBRARY_PATHS) $^ -o $@ $(LIBS)
	chmod +x $(TARGET)

# Clean up the build
clean:
	rm -f $(TARGET)

# Phony targets
.PHONY: all clean
