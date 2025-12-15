# Makefile for CSC840 Lab 15 (FINAL) - Simulated Malware Beacon
# Targets:
#   make easy      -> debug-friendly build (symbols, no optimization)
#   make difficult -> stripped/optimized build (harder to reverse)
#   make clean     -> remove build artifacts

CC      := gcc
SRC     := beacon.c

EASY_BIN := beacon
HARD_BIN := beacon_stripped

CFLAGS_COMMON := -Wall -Wextra -Wpedantic
LDFLAGS_COMMON :=

.PHONY: all easy difficult clean

all: easy

easy: $(EASY_BIN)

difficult: $(HARD_BIN)

$(EASY_BIN): $(SRC)
	$(CC) $(CFLAGS_COMMON) -O0 -g -o $@ $< $(LDFLAGS_COMMON)

$(HARD_BIN): $(SRC)
	$(CC) $(CFLAGS_COMMON) -O2 -s -o $@ $< $(LDFLAGS_COMMON)

clean:
	rm -f $(EASY_BIN) $(HARD_BIN)
