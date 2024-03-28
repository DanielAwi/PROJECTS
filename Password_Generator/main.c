#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "alphabet.h"
#include "information_content.h"
#include "pw_generator.h"

int main(int argc, char **argv) {

    if (argc < 3) {
        printf("Pass more Arguments!\n");
        return 1;
    }

    srand(time(NULL));

    long length = strtol(argv[1], NULL, 10);

    long count = strtol(argv[2], NULL, 10);

    bool alphabet_flags[128];

    for (int i = 0; i < 128; ++i) {
        alphabet_flags[i] = false;
    }

    if (argc == 3) {
        process_luds_flags("-luds", alphabet_flags);
    }

    for (int i = 3; i < argc; ++i) {
        if (argv[i][0] == '-') {

            process_luds_flags(argv[i], alphabet_flags);
        } else {

            process_alphabet(argv[i], alphabet_flags);
        }
    }

    char alphabet[128];
    calculate_alphabet(alphabet_flags, alphabet);

    printf("Using alphabet: %s\n", alphabet);

    for (long i = 0; i < count; ++i) {
        printf("Password %ld:\n", i + 1);
        char password[100];
        gen_password(length, alphabet, password);
        printf("Password: %s\n", password);
        double ic = approx_information_content(password);
        printf("Information content: %.2lf bits\n", ic);
    }

    return 0;
}
