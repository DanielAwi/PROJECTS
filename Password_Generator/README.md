Password Generator

This C program generates passwords based on user-defined parameters such as length and character set. It also calculates the information content of each generated password.

Prerequisites
C compiler (e.g., GCC)

Usage
Download the source code files (main.c, alphabet.h, information_content.h, pw_generator.h) and place them in the same directory.
Open a terminal or command prompt.
Navigate to the directory where the source code files are saved.

Compile the program by executing the following command:
gcc -o pw_generator main.c

Run the program by executing the following command and passing the required arguments:
./pw_generator <password_length> <number_of_passwords> [flags] [custom_alphabets]

<password_length>: Length of each password.
<number_of_passwords>: Number of passwords to generate.
[flags]: Optional flags to specify character sets. Use -luds to include lowercase letters, uppercase letters, digits, and symbols. Additional flags can be added for custom character sets.
[custom_alphabets]: Optional custom character sets. For example, -special can be used to include special characters.

Example usage:
./pw_generator 8 5 -luds -special

Functionality
This program utilizes several header files (alphabet.h, information_content.h, pw_generator.h) to perform the following tasks:

Generate passwords with specified length and character set.
Calculate the information content of each generated password.
Handle command-line arguments to customize password generation.
In the main() function, the program first checks if the required number of arguments is provided. It then processes the command-line arguments to determine the length of passwords, the number of passwords to generate, and the character sets to include. Finally, it generates the specified number of passwords, prints them along with their information content.

Contributors
Awi Daniel

Feel free to contribute to this project by forking it and submitting pull requests. If you encounter any issues or have suggestions for improvements, please create an issue in the repository.