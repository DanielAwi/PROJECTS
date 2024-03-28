#include <stdio.h>
#include <ctype.h>
#include <math.h>
#include <string.h>
#include "information_content.h"

int approximate_alphabet(char *str) {
    int lowercase = 0, uppercase = 0, digits = 0, symbols = 0;

    for (int i = 0; str[i] != '\0'; i++) {
        if (islower(str[i])) {
            lowercase = 26;
        } else if (isupper(str[i])) {
            uppercase = 26;
        } else if (isdigit(str[i])) {
            digits = 10;
        } else {
            symbols = 32;
        }
    }

    return lowercase + uppercase + digits + symbols;
}

double information_content(int length, int alphabet_size) {
    return length * log2(alphabet_size);
}

double approx_information_content(char *str) {
    int alpha = approximate_alphabet(str);
    return information_content(strlen(str), alpha);
}
