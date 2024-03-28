#include <stdio.h>
#include <math.h>
#include <ctype.h>
#include <string.h>


int approximate_alphabet(char *str);
double information_content(int alphabet_size, size_t length);

int main() {
    char str[101];

    printf("Enter the string: ");
    scanf("%100s", str);

    int alphabet_size = approximate_alphabet(str);
    size_t length = strlen(str);

    printf("Approximate alphabet: %d\n", alphabet_size);
    printf("Length: %zu\n", length);
    printf("Information Content: %.2f\n", information_content(alphabet_size, length));

    return 0;
}

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


double information_content(int alphabet_size, size_t length) {
    return length * log2(alphabet_size);
}
