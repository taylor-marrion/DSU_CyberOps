# Makefile for CSC840 Lab 15 (FINAL) - Simulated Malware Beacon
# Targets:
#   make plaintext         -> plaintext config (no encoding, easiest to reverse)
#   make encoded           -> XOR-encoded config, symbols included
#   make encoded_stripped  -> XOR-encoded config, stripped/optimized (harder to reverse)
#   make clean             -> remove build artifacts

CC := gcc

SRC := beacon.c

CFLAGS_COMMON := -Wall -Wextra -Wpedantic
LDFLAGS_COMMON :=

PLAINTEXT_BIN := beacon_plaintext
ENC_BIN       := beacon_encoded
ENC_STRIP_BIN := beacon_encoded_stripped

.PHONY: all plaintext encoded encoded_stripped clean

all: plaintext

# 1) Plaintext (not encoded)
plaintext: $(PLAINTEXT_BIN)

$(PLAINTEXT_BIN): $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 -g -o $@ $< $(LDFLAGS_COMMON)

# 2) Encoded (not stripped)
encoded: $(ENC_BIN)

$(ENC_BIN): $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 -g -DENCODED_CONFIG -o $@ $< $(LDFLAGS_COMMON)

# 3) Encoded + stripped
encoded_stripped: $(ENC_STRIP_BIN)

$(ENC_STRIP_BIN): $(SRC)
	$(CC) $(CFLAGS_COMMON) -O2 -s -DENCODED_CONFIG -o $@ $< $(LDFLAGS_COMMON)

clean:
	rm -f $(PLAINTEXT_BIN) $(ENC_BIN) $(ENC_STRIP_BIN)
