PASSWORD CRACKING TOOL

This Python script is a password cracking tool designed to crack hashed passwords using two different methods: lexicographic crack and random crack. It supports both SHA-256 and PBKDF2 hashing algorithms. The script reads hashed passwords from input files, attempts to crack them using different password generation strategies, and writes the cracked passwords and performance metrics to output files.

DEPENDENCIES
Passlib for PBKDF2 hashing algorithm (pbkdf2_sha256)

USAGE
1. Input Files: Provide input files containing hashed passwords.
sha256_hash1.txt and sha256_hash2.txt for SHA-256 hashing.
pbkdf2_hash1.txt and pbkdf2_hash2.txt for PBKDF2 hashing.

2. Run the Script: Execute the script by running the main function in a Python environment:
python script_name.py

3. Output Files:
Cracked passwords are saved in passwords1.txt and passwords2.txt.
Average cracking time and attempts are saved in averages.txt.

CODE STRUCTURE
Hash Generation
generate_passwords(length): Generates lexicographically ordered passwords of specified length.
generate_passwords_random(length): Generates randomly ordered passwords of specified length.
read_hashes(filename): Reads hashed passwords from a file.

Cracking Methods
crack_hashes(hashes, passwords): Cracks SHA-256 hashed passwords using lexicographic or random password generation.
crack_pbkdf2_hashes(hashes): Cracks PBKDF2 hashed passwords using lexicographic and random password generation.

Main Functionality
main(): Orchestrates the entire process.
Reads SHA-256 hashed passwords.
Performs lexicographic and random cracking, calculates averages, and writes results.
Reads PBKDF2 hashed passwords and cracks them using both lexicographic and random methods.

OUTPUT
Cracked passwords are printed on the console.
Average cracking time and attempts are saved in averages.txt.
Cracked passwords are saved in passwords1.txt and passwords2.txt.