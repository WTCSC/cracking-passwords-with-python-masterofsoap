import argparse
import hashlib

# Supported hash algorithms
ALGORITHMS = {
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
    'md5': hashlib.md5
}

def crack_passwords(password_file, dictionary_file, algorithm='sha256', verbose=False):
    # Choose the hashing algorithm
    hash_func = ALGORITHMS.get(algorithm, hashlib.sha256)

    # Read the passwords and hashed values from the file
    with open(password_file, 'r') as pw_file:
        password_data = [line.strip().split(':') for line in pw_file.readlines()]

    # Read the dictionary file
    with open(dictionary_file, 'r') as dict_file:
        dictionary = [line.strip() for line in dict_file.readlines()]

    # Start cracking
    cracked = 0
    for username, hashed_password in password_data:
        for password in dictionary:
            hashed_attempt = hash_func(password.encode()).hexdigest()

            if hashed_attempt == hashed_password:
                print(f"{username}:{password}")
                cracked += 1
                if verbose:
                    print(f"Cracked {username}'s password")
                break
# Prints the results
    if verbose:
        print(f"Total passwords cracked: {cracked}")
        print(f"Passwords not cracked: {len(password_data) - cracked}")

if __name__ == "__main__":
    # Argument parser setup
    parser = argparse.ArgumentParser(description='Jill the Heckler: A Password Cracker')

    # Add required arguments for the password and dictionary filesk
    parser.add_argument('password_file', help='File containing usernames and hashed passwords')
    parser.add_argument('dictionary_file', help='File containing dictionary words to try as passwords')

    # Add optional argument for hash algorithm
    parser.add_argument('-a', '--algorithm', help='Hash algorithm to use (sha256, sha512, md5)', default='sha256')

    # Add the verbose flag
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    # Parse the arguments
    args = parser.parse_args()

    # Call the crack_passwords function with parsed arguments
    crack_passwords(args.password_file, args.dictionary_file, args.algorithm, args.verbose)