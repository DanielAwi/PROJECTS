#include <stdlib.h>
#include <string.h>
#include "pw_generator.h"

void gen_password(int length, char *alphabet, char *output) {
    int len_of_alphabet = strlen(alphabet);
    for (int i = 0; i < length; ++i) {
        output[i] = alphabet[rand_int(0, len_of_alphabet - 1)];
    }
}

int rand_int(int a, int b) {

    int range = b - a + 1;
    int discarding_limit = RAND_MAX - (RAND_MAX % range);

    for (;;) {

        int initial = rand();
        if (initial > discarding_limit) {

            continue;
        }
        int scaled = initial % range;

        int shift = scaled + a;
        return shift;
    }
}
