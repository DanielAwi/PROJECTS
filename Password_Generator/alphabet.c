#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "alphabet.h"

void process_luds_flags(char *luds, bool *alphabet) {

    for (int i = 0; luds[i] != '\0'; ++i) {
        if (luds[i] == 'l') {

            set_all_lowercase(alphabet);
        } if (luds[i] == 'u') {

            set_all_uppercase(alphabet);
        } if (luds[i] == 'd') {

            set_all_digit(alphabet);
        } if (luds[i] == 's') {

            set_all_symbols(alphabet);
        }
    }
}
void set_all_uppercase(bool *alphabet){
    for(char c = 'A'; c <= 'Z'; ++c) {
        alphabet[c] = true;
    }

}
void set_all_symbols(bool *alphabet){
    const char *symbols = "`~!@#$%^&*()-_=+[]{}\\|;:'\",<.>/?";
    for (int i = 0; symbols[i] != '\0'; i++) {
        alphabet[symbols[i]] = true;
    }
}

void set_all_lowercase(bool *alphabet) {
    for (char c = 'a'; c <= 'z'; ++c) {
        alphabet[c] = true;
    }
}

void set_all_digit(bool *alphabet) {
    for (char c = '0'; c <= '9'; ++c) {
        alphabet[c] = true;
    }
}


void process_alphabet(char *param, bool *alphabet) {
    for (int i = 0; param[i] != '\0'; ++i) {
        if (isgraph(param[i])) {
            alphabet[param[i]] = true;
        }
    }
}

void calculate_alphabet(bool *alphabet, char *output) {
    int out_letter = 0;
    for (int i =0; i < 128; ++i) {
        if (alphabet[i]) {
            output[out_letter] = i;
            ++out_letter;
        }
    }
    output[out_letter] = '\0';
}
