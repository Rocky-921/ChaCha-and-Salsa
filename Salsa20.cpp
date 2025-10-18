#define _POSIX_C_SOURCE 199309L
#include <iostream>
#include <cmath>
#include <cstdint>
#include <chrono>
#include <time.h>

#define PLUS(v,w) ((v+w)&0xffffffff)

using namespace std;

bool log_capture = false;

void LOG(string message){
    if(log_capture){
        cout << message << endl;
    }
}

void print_state(uint32_t *S){
    if(!log_capture)
        return;
    // only print when log_capture is true

    cout << "State Matrix:" << endl;
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            printf("%08x ", S[i*4 + j]);
        }
        cout << endl;
    }
    cout << "--------------------------\n";
}

void print_hex_arr(const unsigned char *arr, size_t len){
    if(!log_capture)
        return;
    for(size_t i=0;i<len;i++){
        printf("%02x ", arr[i]);
    }
    cout << endl;
}

uint32_t getWord(const unsigned char *input){
    uint32_t word = 0;
    // word is stored in little-endian format -> word = input[3] input[2] input[1] input[0]

    for(int i = 0; i < 4; i++){
        word |= (input[i] << (i * 8));
    }
    return word;
}

void init_state(uint32_t *S, const unsigned char *key, const unsigned char *iv){
    // Assuming only 32 byte key
    const unsigned char *constants = (const unsigned char *)"expand 32-byte k";

    // Initialize State Matrix:-
    /*
    S->C0    K0    K1    K2
       K3    C1    V0    V1
       T0    T1    C2    K4
       K5    K6    K7    C3
    */
    for(int i=1;i<5;i++){
        S[i] = getWord(key + (i-1)*4);
    }
    for(int i=11;i<15;i++){
        S[i] = getWord(key + (i-7)*4);
    }
    //----key bytes stored-----------------
    for(int i=0;i<4;i++){
        S[5*i] = getWord(constants + i*4);
    }
    //----constant bytes stored------------
    S[6] = getWord(iv);
    S[7] = getWord(iv + 4);
    //----nonce stored---------------------
    S[8] = getWord(iv + 8); // counter low
    S[9] = getWord(iv + 12); // counter high
    //----counter stored ------------------
}

uint32_t rotateLeft(uint32_t x, int n) {
    return (((x << n) | (x >> (32 - n))) & 0xffffffff);
}

void quarterRound(uint32_t *S, int i0, int i1, int i2, int i3){
    
    // As per Salsa20 Configuration

    S[i1] ^= rotateLeft(PLUS(S[i0], S[i3]), 7);     // z1 = y1^((y0+y3)<<<7)
    S[i2] ^= rotateLeft(PLUS(S[i1], S[i0]), 9);     // z2 = y2^((z1+y0)<<<9)
    S[i3] ^= rotateLeft(PLUS(S[i2], S[i1]), 13);    // z3 = y3^((z2+z1)<<<13)
    S[i0] ^= rotateLeft(PLUS(S[i3], S[i2]), 18);    // z0 = y0^((z3+z2)<<<18)
}

void encrypt_block(uint32_t *S, unsigned char *output){
    // Implement the block encryption using the Salsa20 algorithm
    uint32_t x[16];
    for(int i=0;i<16;i++){
        x[i] = S[i];
    }

    // do 10-Double Rounds 
    for(int i=0;i<10;i++){
        // Column Round
        quarterRound(x, 0, 4, 8, 12);
        quarterRound(x, 5, 9, 13, 1);
        quarterRound(x, 10, 14, 2, 6);
        quarterRound(x, 15, 3, 7, 11);
        
        // Row Round
        quarterRound(x, 0, 1, 2, 3);
        quarterRound(x, 5, 6 ,7, 4);
        quarterRound(x, 10, 11, 8, 9);
        quarterRound(x, 15, 12, 13, 14);
        LOG("Executed " + to_string(i + 1) + " Double-Round(s)\n");
        print_state(x);
    }

    // S + Double-Round10(S)
    for(int i=0;i<16;i++){
        x[i] = PLUS(x[i], S[i]);
    }

    // Get 64 bytes from the final state to xor with plaintext
    for(int i=0;i<16;i++){
        output[4*i] = (unsigned char)(x[i]&0xff);
        output[4*i+1] = (unsigned char)((x[i] >> 8)&0xff);
        output[4*i+2] = (unsigned char)((x[i] >> 16)&0xff);
        output[4*i+3] = (unsigned char)((x[i] >> 24)&0xff);
    }

    LOG("Final Array to take the plaintext xor with (hex): ");
    print_hex_arr(output, 64);
}

void encrypt(char *msg, size_t msg_len, uint32_t *S, unsigned char *ciphertext){
    int ttl_blocks = ceil(msg_len / 64.0);
    LOG("Total Blocks made from plaintext: " + to_string(ttl_blocks) + "\n");

    for(int curr_block=0; curr_block<ttl_blocks; curr_block++){
        // Process each 64-byte block
        unsigned char output[64];
        encrypt_block(S, output);

        // 64 bytes or less
        for(int i=curr_block*64;i<fmin((curr_block+1)*64, msg_len);i++){
            ciphertext[i] = (msg[i] ^ output[i % 64]);
        }
        LOG("Processed block " + to_string(curr_block + 1) + " of " + to_string(ttl_blocks));
        // Increment Counter
        S[8] = PLUS(S[8], 1);
        if(S[8] == 0){
            S[9] = PLUS(S[9], 1);
        }
    }
    ciphertext[msg_len] = '\0';
}

void decrypt(char *ciphertext, size_t msg_len, uint32_t *S, unsigned char *decrypted){
    // Encrypting the ciphertext using initial state to get back the plaintext
    encrypt(ciphertext, msg_len, S, decrypted);
}

int main(int argc, char* argv[]) {
    if(argc < 3){
        cerr << "Usage: " << argv[0] << " <input_file> <LOG_Capture(Y/N)> <optional Plaintext input file> <optional output file>" << endl;
        return 1;
    }

    log_capture = (argv[2][0] == 'Y' || argv[2][0] == 'y');
    
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        cerr << "Error opening file" << endl;
        return 1;
    }

    unsigned char key[32];
    unsigned char iv[16];

    // Read 32 hex bytes for key
    for (int i = 0; i < 32; i++) {
        uint32_t val;
        if (fscanf(fp, "%2x", &val) != 1) {
            fprintf(stderr, "Error: failed to read key byte %d\n", i);
            return 1;
        }
        key[i] = (unsigned char) val;
    }

    // Read 8 hex bytes for IV, 8 next bytes for counter
    for (int i = 0; i < 16; i++) {
        uint32_t val;
        if (fscanf(fp, "%2x", &val) != 1) {
            fprintf(stderr, "Error: failed to read iv byte %d\n", i);
            return 1;
        }
        iv[i] = (unsigned char) val;
    }

    char *msg = NULL;
    size_t len = 0;
    ssize_t msg_len;
    if(argc >= 3){
        FILE *input_file = fopen(argv[3], "rb");
        if (!input_file) {
            cerr << "Error opening input file" << endl;
            return 1;
        }

        fseek(input_file, 0, SEEK_END);
        long file_size = ftell(input_file);
        fseek(input_file, 0, SEEK_SET);

        msg = (char *)malloc(file_size + 1);
        if (!msg) {
            cerr << "Error allocating memory" << endl;
            return 1;
        }

        fread(msg, 1, file_size, input_file);
        fclose(input_file);

        msg[file_size] = '\0';
        msg_len = file_size;
    }else{
        msg_len = getline(&msg, &len, stdin);

        if (msg_len == -1) {
            perror("getline");
            exit(1);
        }
        if(msg[msg_len-1] == '\n'){
            msg[msg_len-1] = '\0';
            msg_len--;
        }
    }

    LOG("--------------------------\nPlaintext: "+(string)msg);
    LOG("Length: " + to_string(msg_len) + "\n--------------------------\n");

    LOG("Key (hex): ");
    print_hex_arr(key, 32);

    LOG("Nonce (hex): ");
    print_hex_arr(iv, 8);
    LOG("Counter (hex): ");
    print_hex_arr(iv + 8, 8);
    
    unsigned char ciphertext[msg_len+1];

    uint32_t S[16]; // initial state
    
    struct timespec start, end;
    //-----------------------------Input Taken-------------------------------------
    
    // Start Timer
    clock_gettime(CLOCK_MONOTONIC, &start);

    init_state(S, key, iv);

    if(log_capture){
        cout << "Initial State:" << endl;
        print_state(S);
    }

    encrypt(msg, msg_len, S, ciphertext);

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);

    LOG("--------------------------\nCiphertext (hex): ");

    print_hex_arr(ciphertext, msg_len);

    cout << "Execution Time: " << elapsed / 1e3 << " microseconds" << endl;

    if(argc==5){
        FILE *output_file = fopen(argv[4], "wb");
        if (!output_file) {
            cerr << "Error opening output file" << endl;
            return 1;
        }

        fwrite(ciphertext, 1, msg_len, output_file);
        fclose(output_file);
    }

    return 0;
}
