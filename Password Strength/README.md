
Information Content Calculator

This C program calculates the information content of a given string based on its approximate alphabet size. Information content measures the amount of information conveyed by a message and is commonly used in fields such as information theory and data compression.

Prerequisites
C compiler (e.g., GCC)

Usage
Download the password_information_content.c file.
Open a terminal or command prompt.
Navigate to the directory where information_content.c is saved.
Compile the program by executing the following command:
gcc -o password_information_content password_information_content.c -lm

Run the program by executing the following command:
./password_information_content

Enter the string when prompted.

Functionality
This program contains the following functions:
approximate_alphabet(char *str): Approximates the size of the alphabet in the input string by counting the occurrence of lowercase letters, uppercase letters, digits, and symbols.
information_content(int alphabet_size, size_t length): Calculates the information content of the string based on its approximate alphabet size and length.
In the main() function, the user is prompted to enter a string. The program then calculates and displays the approximate alphabet size, length of the string, and information content.

Contributors
Awi Daniel

Feel free to contribute to this project by forking it and submitting pull requests. If you encounter any issues or have suggestions for improvements, please create an issue in the repository.