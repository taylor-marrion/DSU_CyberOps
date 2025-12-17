# CSC840 Lab 15 (FINAL)  
## Reverse Engineering an Obfuscated Linux Beacon

---

## General Information
**Author:** Taylor Marrion  
**Date:** 12/17/2025  
**Course:** CSC840 - Cyber Operations  

**Description:**  
This project extends earlier CSC840 malware and network analysis labs by examining how simple encoding techniques are used to hide malware configuration data in Linux ELF binaries, and how reverse engineering techniques can be applied to recover that information. A safe, simulated HTTP beacon is analyzed in both plaintext and encoded forms to demonstrate how obfuscation impacts static analysis and how analysts adapt when obvious indicators are removed.

---

## Why You Should Care
In previous CSC840 labs, malware analysis focused heavily on observable indicators such as plaintext strings, network traffic, and basic behavioral artifacts. While these techniques are effective against many samples, real-world malware frequently employs encoding or encryption to obscure configuration data and evade “easy” detection.

Obfuscation does not eliminate malicious behavior, it only hides static indicators. Network beacons must still decode their configuration at runtime in order to construct requests, communicate with command-and-control infrastructure, and parse responses. Understanding how to identify, locate, and reverse these decoding mechanisms is a critical skill for analysts working with modern malware.

This project demonstrates how reverse engineering bridges the gap between traditional static analysis and runtime behavior, reinforcing that obfuscation delays analysis but does not prevent it.

---

## Three Main Ideas

1. **Obfuscation Removes Indicators, Not Behavior**  
   Encoding configuration data defeats simple string-based detection, but the underlying network behavior and program structure remain observable through imports and control flow.

2. **Analysts Hunt Decode Logic, Not Strings**  
   When configuration data is no longer readable, analysts pivot to identifying runtime decoding routines by anchoring on known behaviors such as message construction and network transmission.

3. **Plaintext Must Exist Before Use**  
   Even encoded malware must decode its configuration before use, creating a window where plaintext data can be recovered through static or dynamic reverse engineering techniques.

---

## Demo / Code Walk-Through
This project includes three builds of the same simulated beacon, all derived from a single source file:

- **`beacon_plaintext`** - Configuration stored as plaintext strings (baseline)
- **`beacon_encoded`** - Configuration stored as XOR-encoded byte arrays
- **`beacon_encoded_stripped`** - Encoded configuration with symbols removed (extension exercise)

The video demonstration focuses on comparing the plaintext and encoded versions using Ghidra. The analysis shows how plaintext configuration disappears in the encoded binary, how imports and control flow still reveal intent, and how the XOR decode routine can be located and used to recover the original configuration values. The stripped variant is discussed briefly as an extension, demonstrating that the same analytical approach applies even when symbol information is removed.

---

## Conclusion / Where to Go Next
This lab builds directly on earlier CSC840 coursework by extending malware analysis into reverse engineering of obfuscated binaries. While simple encoding techniques are effective against basic detection methods, they do not fundamentally prevent analysis. By focusing on behavior, decode-before-use patterns, and data flow, analysts can reliably recover hidden configuration data.

Future work could explore stronger cryptographic protections, automated configuration extractors, or dynamic analysis techniques that recover decoded data directly from memory at runtime.

---

## Additional Resources
- [Video Demonstration](https://youtu.be/m-Gw3BVZ6jM)
- [NSA Ghidra Reverse Engineering Framework](https://www.nsa.gov/ghidra)
- [IDA Free (Hex-Rays)](https://hex-rays.com/ida-free/)
- [Practical Malware Analysis - Sikorski & Honig](https://nostarch.com/malware)
- [FLARE-On Reverse Engineering Challenges](https://flare-on.com/)

---

### Notes
- All binaries are **harmless by design** and communicate only with a localhost listener.
- No persistence, privilege escalation, or data exfiltration is implemented.
