import hashlib
import random
from string import ascii_lowercase
from itertools import product 
from timeit import default_timer as timer
from passlib.hash import pbkdf2_sha256

def generate_passwords(length=5):
    return [''.join(c) for c in product(ascii_lowercase, repeat=length)]

def generate_passwords_random(length=5):
    passwords = [''.join(c) for c in product(ascii_lowercase, repeat=length)]
    random.shuffle(passwords)
    return passwords

def read_hashes(filename):
    with open(filename) as f:
        return f.read().splitlines()

def crack_hashes(hashes, passwords):
    cracked_passwords = []
    ttc_total = 0
    atc_total = 0
    num_cracked = 0

    for h in hashes:
        salt, hash_value = h.split('$')
        new_salt = bytes.fromhex(salt)

        start = timer()
        attempts = 0

        for password in passwords:
            attempts += 1

            if hashlib.sha256(new_salt + password.encode('utf-8')).hexdigest() == hash_value:
                end = timer()
                ttc = end - start

                ttc_total += ttc
                atc_total += attempts
                num_cracked += 1

                cracked_passwords.append(password)

                print(f"Cracked: {password}")
                print(f"TTC: {ttc:.2f} seconds")
                print(f"Attempts: {attempts}")
                break

    return cracked_passwords, ttc_total, atc_total, num_cracked

def main():
    # Read hashes
    hashes = read_hashes('sha256_hash1.txt') 
    hashes2 = read_hashes('sha256_hash2.txt') 

    # Write results
    with open('passwords1.txt', 'w') as f:

        # First crack
        passwords1 = generate_passwords()
        cracked_passwords1, ttc_total, atc_total, num_cracked = crack_hashes(hashes, passwords1)

        for password in cracked_passwords1:
            f.write(f"{password}\n")

        # Calculate averages            
        avg_ttc1 = ttc_total / num_cracked
        avg_atc1 = atc_total / num_cracked

        with open('averages.txt', 'w') as f:

            f.write("Average TTC & ATC - S1\n")

            # Print first averages
            f.write("\nLexicographic Crack:\n")  
            f.write(f"Average TTC: {avg_ttc1:.2f}\n")
            f.write(f"Average ATC: {avg_atc1:.2f}\n")

        passwords2 = generate_passwords_random()
        cracked_passwords2, ttc_total, atc_total, num_cracked = crack_hashes(hashes, passwords2)

        # Calculate averages            
        avg_ttc2 = ttc_total / num_cracked
        avg_atc2 = atc_total / num_cracked

        with open('averages.txt', 'a') as f:

            # Print first averages
            f.write("\nRandom Crack:\n")  
            f.write(f"Average TTC: {avg_ttc2:.2f}\n")
            f.write(f"Average ATC: {avg_atc2:.2f}\n")

    # Write results
    with open('passwords2.txt', 'w') as f:

        # First crack
        passwords1 = generate_passwords()
        cracked_passwords1, ttc_total, atc_total, num_cracked = crack_hashes(hashes2, passwords1)

        for password in cracked_passwords1:
            f.write(f"{password}\n")

        # Calculate averages              
        avg_ttc1 = ttc_total / num_cracked
        avg_atc1 = atc_total / num_cracked

        with open('averages.txt', 'a') as f:

            f.write("\nAverage TTC & ATC - S2\n")

            # Print first averages
            f.write("\nLexicographic Crack:\n")  
            f.write(f"Average TTC: {avg_ttc1:.2f}\n")
            f.write(f"Average ATC: {avg_atc1:.2f}\n")

        passwords2 = generate_passwords_random()
        cracked_passwords2, ttc_total, atc_total, num_cracked = crack_hashes(hashes2, passwords2)

        # Calculate averages              
        avg_ttc2 = ttc_total / num_cracked
        avg_atc2 = atc_total / num_cracked

        with open('averages.txt', 'a') as f:

            # Print first averages
            f.write("\nRandom Crack:\n")  
            f.write(f"Average TTC: {avg_ttc2:.2f}\n")
            f.write(f"Average ATC: {avg_atc2:.2f}\n")

    def crack_pbkdf2_hashes(hashes):

        for h in hashes:

            # Try lexicographic passwords  
            for password in generate_passwords():

                if pbkdf2_sha256.verify(password, h):
                    print(f"Cracked: {password}")
                    break 

            # Try random passwords
            for password in generate_passwords_random():

                if pbkdf2_sha256.verify(password, h):
                    print(f"Cracked: {password}")
                    break

    with open('pbkdf2_hash1.txt') as f:
        hashes = f.read().splitlines()   

    with open('pbkdf2_hash2.txt') as f:
        hashes = f.read().splitlines()

    crack_pbkdf2_hashes(hashes)

if __name__ == "__main__":
    main()
