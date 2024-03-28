#ifndef C_PROJECT_ALPHABET_H
#define C_PROJECT_ALPHABET_H
#include <stdbool.h>

void process_luds_flags(char *luds, bool *alphabet);
void process_alphabet(char *param, bool *alphabet);

void set_all_lowercase(bool *alphabet);
void set_all_digit(bool *alphabet);
void set_all_symbols(bool *alphabet);
void set_all_uppercase(bool *alphabet);

void calculate_alphabet(bool *alphabet, char *output);

#endif
