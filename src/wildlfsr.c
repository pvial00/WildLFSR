#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ganja.c"

int keylen = 16;
struct wild_state {
    uint32_t lfsr[4];
};

uint32_t uregister1(uint32_t r) {
    r >>=1;
    return ((r << 4) ^ (r << 3) ^ (r >> 4) ^ (r >> 3));
}

uint32_t uregister2(uint32_t r) {
    r >>=1;
    return ((r << 3) ^ (r << 2) ^ (r >> 4) ^ (r >> 1));
}

uint32_t uregister3(uint32_t r) {
    r >>= 1;
    return((r << 1) ^ (r << 2) ^ (r >> 3) ^ (r >> 1));
}

uint32_t uregister4(uint32_t r) {
    r >>= 1;
    return((r << 2) ^ (r << 5) ^ (r >> 4) ^ (r >> 2));
}

uint32_t getregister_output(struct wild_state *state) {
    return (state->lfsr[0] ^ state->lfsr[1] ^ state->lfsr[2] ^ state->lfsr[3]);
}

void ksa(struct wild_state *state, unsigned char * key) {
    state->lfsr[0] = (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
    state->lfsr[1] = (key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7];
    state->lfsr[2] = (key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11];
    state->lfsr[3] = (key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15];
    
    uint32_t temp = 0x00000001;
    temp = (state->lfsr[0] + state->lfsr[1] + state->lfsr[2] + state->lfsr[3] + temp) & 0xFFFFFFFF;
    for (int i = 0; i < 4; i++) {
        temp = (state->lfsr[0] + state->lfsr[1] + state->lfsr[2] + state->lfsr[3] + temp) & 0xFFFFFFFF;
        state->lfsr[i] = temp;
    }
}

int main(int arc, char *argv[]) {
    unsigned char * key[16] = {0};
    FILE *outfile, *infile;
    uint8_t k[4];
    uint32_t lfsr_out;
    struct wild_state state;
    int c = 0;
    char *inf = argv[1];
    char *outf = argv[2];
    char *password = argv[3];
    ganja_kdf(password, strlen(password), key, 10000, keylen, "WildLFSRCipherv1");
    ksa(&state, key);
    int v = 4;
    int x, i;
    int t = 0;
    infile = fopen(inf, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    unsigned char data[v];
    int blocks = fsize / 4;
    int fsize_extra = fsize % 4;
    int extra = 0;
    if (fsize_extra != 0) {
        extra = 1; }
    outfile = fopen(outf, "wb");
    for (i = 0; i < (blocks + extra); i++) {
        fread(data, 1, v, infile);
        state.lfsr[0] = uregister1(state.lfsr[0]);
        state.lfsr[1] = uregister2(state.lfsr[1]);
        state.lfsr[2] = uregister3(state.lfsr[2]);
        state.lfsr[3] = uregister4(state.lfsr[3]);
        lfsr_out = getregister_output(&state);
        k[3] = (lfsr_out & 0x000000FF);
        k[2] = (lfsr_out & 0x0000FF00) >> 8;
        k[1] = (lfsr_out & 0x00FF0000) >> 16;
        k[0] = (lfsr_out & 0xFF000000) >> 24;
        if (i == (blocks) && (fsize_extra != 0)) {
            v = fsize_extra; }
        for (x = 0; x < v; x++) {
            data[x] = data[x] ^ k[x];
        }
        fwrite(data, 1, v, outfile);
    }
    fclose(outfile);
    fclose(infile);
}
