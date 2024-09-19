import argparse
import hashlib
import time

algorithims = {
    'sha256':hashlib.sha256,
    'sha512':hashlib.sha256,
    'md6':hashlib.md5
}

def crack_passowrds(password_file, dictionary_file, algorithims='sha256', verbose=False):
    hash_func = algorithims.get(algorithims, hashlib.sha256)
    with open(password_file, 'r') as pw_file:
        password_data = [line.strip().split(':') for line in pw_file.readlines()]
    with open(dictionary_file, 'r') as dict_file:
        dictionary = [line.strip() for line in dict_file.readlines()]
    cracked = 0
    for username, hashed_password in password_data:
        for password in dictionary:
            hashed_attempt = hash_func(password.encode()).hexdigest()

            if hashed_attempt == hashed_password:
                print(f"{username}:{password}")
                cracked += 1
                if verbose:
                    print(f"Cracked {username}'s password in {time.time():.4f} seconds")
                break
    
    if verbose:
        print(f"Total passwords cracked: {cracked}")
        print(f"Passwords NOT cracked: {len(password_data) - cracked}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Jill the Hacker: A python password hacker')
    parser.add_argument('password_file', help='File containing usernames and hashed passwords')
    parser.add_argument('dictionary_file', help='File containing words to try as passwords')
    parser.add_argument('-a', '--alcorithim', help='Hash algorithim to use (sha256, sha512, md5)')
