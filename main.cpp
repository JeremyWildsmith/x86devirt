#include "decrypt.h"

#include <iostream>

using namespace std;

typedef __attribute__((stdcall)) void (*DecryptInstruciton_t)(void* pInstrBufferOffset1, unsigned int instrLengthMinusOne, unsigned int relativeOffset);

int main() {

    unsigned char buffer[] = {0xDF, 0xEE, 0x01, 0x72};
    DecryptInstruciton_t p = (DecryptInstruciton_t)(&decryptInstruction);
    p(buffer, sizeof(buffer), 0x2A);


    for(char b : buffer) {
        printf("%X, ", b & 0xFF);
    }
    return 0;
}