#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

static void write_hex_line(FILE *out, const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        fprintf(out, "%02x", buf[i]);
    }
    fprintf(out, "\n");
}

int main(int argc, char *argv[]) {

    if (argc != 3) {
        printf("Usage: %s <MessagesFile.txt> <Mx>\n", argv[0]);
        return 1;
    }

    char *messages_file = argv[1];
    char *mx = argv[2];

    

    // Read 8 messages 
    FILE *f = fopen(messages_file, "r");
    if (!f) {
        perror("Error opening messages file");
        return 1;
    }

    unsigned char messages[8][32];
    char line[256];

    for (int i = 0; i < 8; i++) {
        if (!fgets(line, sizeof(line), f)) {
            fprintf(stderr, "Error reading line %d\n", i + 1);
            fclose(f);
            return 1;
        }

        // Remove \r and \n 
        line[strcspn(line, "\r\n")] = '\0';

        size_t len = strlen(line);

        if (len != 32) {
            fprintf(stderr, "Error: line %d length is %zu (expected 32)\n", i + 1, len);
            fclose(f);
            return 1;
        }

        memcpy(messages[i], line, 32);
    }

    fclose(f);

    // Hash the 8 leaf messages 
    unsigned char L0[8][32];
    for (int i = 0; i < 8; i++) {
        SHA256(messages[i], 32, L0[i]);
    }

    // Build the Merkle tree 
    unsigned char L1[4][32];
    unsigned char L2[2][32];
    unsigned char L3[1][32];

    for (int i = 0; i < 4; i++) {
        unsigned char concat[64];
        memcpy(concat, L0[i * 2], 32);
        memcpy(concat + 32, L0[i * 2 + 1], 32);
        SHA256(concat, 64, L1[i]);
    }

    for (int i = 0; i < 2; i++) {
        unsigned char concat[64];
        memcpy(concat, L1[i * 2], 32);
        memcpy(concat + 32, L1[i * 2 + 1], 32);
        SHA256(concat, 64, L2[i]);
    }

    {
        unsigned char concat[64];
        memcpy(concat, L2[0], 32);
        memcpy(concat + 32, L2[1], 32);
        SHA256(concat, 64, L3[0]);
    }


    // Write TheRoot.txt 
    FILE *root_file = fopen("TheRoot.txt", "w");
    if (!root_file) {
        perror("Error opening TheRoot.txt");
        return 1;
    }
    // Write root hash without trailing newline
    for (int i = 0; i < 32; i++) {
    fprintf(root_file, "%02x", L3[0][i]);
}
fprintf(root_file, "\n");
fclose(root_file);


    // Parse mx and compute authentication path 
    // Validate mx format 
    if (mx[0] != 'M' || mx[1] == '\0') {
        fprintf(stderr, "Error: invalid mx format (expected M1-M8)\n");
        return 1;
    }

    int msg_num = atoi(mx + 1);
    if (msg_num < 1 || msg_num > 8) {
        fprintf(stderr, "Error: message number must be 1-8\n");
        return 1;
    }

    int idx = msg_num - 1; // Convert to 0 based index

    // Compute sibling indices for 8 leaves:
    int sib0 = idx ^ 1;
    int sib1 = (idx / 2) ^ 1;
    int sib2 = ((idx / 2) / 2) ^ 1;

    // Write ThePath.txt 
    FILE *path_file = fopen("ThePath.txt", "w");
    if (!path_file) {
        perror("Error opening ThePath.txt");
        return 1;
    }
    write_hex_line(path_file, L0[sib0], 32);
    write_hex_line(path_file, L1[sib1], 32);
    write_hex_line(path_file, L2[sib2], 32);
    fclose(path_file);

    return 0;
}
