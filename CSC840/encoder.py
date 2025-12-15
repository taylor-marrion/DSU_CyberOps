#s = "Mozilla/5.0 (X11; Linux x86_64) CSC840-Beacon/1.0"
#s = "/checkin"
s = "{\"id\":\"CSC840-AGENT\",\"op\":\"ping\",\"ver\":\"1.0\"}"

encoded = [ord(c) ^ 0x2A for c in s]

# Pretty-print like a C array
for i, b in enumerate(encoded):
    print(f"0x{b:02x},", end="")
    if (i + 1) % 16 == 0:
        print()
