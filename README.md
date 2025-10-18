# Salsa20 & ChaCha20 Stream Cipher Implementations

This project contains two C++ implementations of the **Salsa20** and **ChaCha20** stream ciphers, each with detailed inline comments for better understanding.

---

## 📁 Files

- **Salsa20.cpp** — Implementation of the Salsa20 cipher with comments  
- **ChaCha20.cpp** — Implementation of the ChaCha20 cipher with comments  

---

## ⚙️ Compilation & Execution

### **Compile**
```bash
g++ <cpp-file>.cpp
```
Run
```bash
./a.out <input_file> <LOG_Capture(Y/N)> <optional_plaintext_file> <optional_output_file>
```
## 🧩 Input File Format
The input_file (e.g., init_state.txt) should contain the key, nonce (IV), and counter, all in hexadecimal format.

For Salsa20
```text
32-byte key
8-byte IV (nonce)
8-byte counter
```
For ChaCha20
```text
32-byte key
12-byte IV (nonce)
4-byte counter
```

📝 Note: A sample file init_state.txt is provided for reference.

## 📥 Input and Output Behavior
- **Plaintext Input File (optional):**
If provided, the program reads the plaintext from this file.
Otherwise, it reads a full line (with spaces) from the console.

- **Output File (optional):**
If provided, the resulting ciphertext is written to this file as raw bytes.
Otherwise, the ciphertext is displayed on the console.

- **LOG_Capture Argument:**
Pass Y to enable logging or N to disable it.

## 🧾 Log Output Includes
The generated logs (when enabled) clearly display:

- Plaintext

- Key used

- Nonce used

- Counter used

- Ciphertext

- State matrix after each double-round

- Final state matrix (as byte array) used for XOR with plaintext

## 🧠 Example Usage
### Sample Setup
- init_state.txt contains key = nonce = counter = 0

- Plaintext: SomeText.txt

### Salsa20
```bash
$ g++ Salsa20.cpp -o salsa
$ ./salsa init_state.txt N SomeText.txt _CS6530_Assgn1_Part1_Encrypted_Salsa.bin
Execution Time: 2426.74 microseconds
```
### ChaCha20
```bash
$ g++ ChaCha20.cpp -o chacha
$ ./chacha init_state.txt N SomeText.txt SomeText_Encrypted_Chacha.bin
Execution Time: 2718.64 microseconds
```

### 📊 File Statistics

| File | Size (bytes) |
|------|---------------|
| SomeText.txt | 43509 |
| SomeText_Encrypted_Salsa.bin | 43509 |
| SomeText_Encrypted_Chacha.bin | 43509 |

> File sizes verified using the `stat` command.

### 🔁 Decryption
Encryption and decryption are symmetric — running the same program on a ciphertext decrypts it.

### Salsa20 Decryption
```bash
$ ./salsa init_state.txt N SomeText_Encrypted_Salsa.bin SomeText_decrypted_Salsa.bin
Execution Time: 2843.2 microseconds
$ diff SomeText_decrypted_Salsa.bin SomeText.txt
```
### ChaCha20 Decryption
```bash
$ ./chacha init_state.txt N SomeText_Encrypted_Chacha.bin SomeText_decrypted_Chacha.bin
Execution Time: 3099.83 microseconds
$ diff SomeText_decrypted_Chacha.bin SomeText.txt
```
The diff command confirms identical plaintext restoration.

## 🧩 Notes
Filenames are appended with _salsa or _chacha for clarity.

Both encryption and decryption use the same function logic.

## 🧑‍💻 Author
Prince Garg
