#include <iostream>
#include <stdint.h>

//https://github.com/jviki/xxtea

/*
 * Decrypt block by XXTEA.
 * Params:
 *   block - block of encrypted data
 *   len   - length of block
 *   key   - 128b key
 */

int count = 0;
int countR = 0;

void decrypt(uint8_t *block, uint32_t len){
    uint32_t  key[4] = {0x9474B8E8, 0xC73BCA7D, 0x53239142, 0xf3c3121a};
    uint8_t z, y;
    uint32_t p, q, e, sum = 0, DELTA = 0x9e3779b9;

    z = block[len - 1];
    y = block[0];

    q = 6 + 52/len;
    sum = q*DELTA ;
    while (sum != 0) {
        e = (sum >> 2) & 3;
        for (p=len-1; p>0; p--)
        {
            z = block[p-1];
            block[p] -= (z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (key[p&3^e]^z);
            y = block[p];
        }
        z = block[len-1];
        block[0] -= (z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (key[p&3^e]^z);
        y =  block[0];
        sum -= DELTA;
    }
}

/*
 * Crypt block by XXTEA.
 * Params:
 *   block - block of input data
 *   len   - length of block
 *   key   - 128b key
 */
void crypt(uint8_t *block, uint32_t len){
    uint32_t  key[4] = {0x9474B8E8, 0xC73BCA7D, 0x53239142, 0xf3c3121a};
    uint8_t z, y;
    uint32_t p, q, e, sum = 0, DELTA = 0x9e3779b9;

    z = block[len - 1];
    y = block[0];

    q = 6 + 52/len;
    printf(">q %d< <len %d>\n",q,len);

    while (q-- > 0) {
        sum += DELTA;                                                           //1
        e = (sum >> 2) & 3;                                                     //2
        count += 3;
        for (p=0; p<len-1; p++) {
            y = block[p+1];                                                     //1
            block[p] += (z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (key[p&3^e]^z);     //14
            z = block[p];
            count+=15;
        }
        y = block[0];
        block[len-1] += (z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (key[p&3^e]^z);     //15
        z = block[len-1];                                                       //1
        count+=16;
        countR++;//count round
    }
}

int main() {
    uint8_t input [] = {0xff, 0x1,0x2, 0x3,0x4,0x5,0x6,0xfa};

    printf("in %x %x %x %x %x %x %x %x\n", input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7]);
    crypt(input, sizeof(input));
    printf(">%d, %d\n",count,countR);
    printf("cr %x %x %x %x %x %x %x %x\n", input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7]);
    decrypt(input, sizeof(input));
    printf("dc %x %x %x %x %x %x %x %x\n\n",input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7]);

    return 0;
}