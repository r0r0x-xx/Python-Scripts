# !/usr/bin/env python3
# Script By r0r0x
# Practice for the OSEP exam
#############################
# Requirements:
# pip3 install wireless

import hashlib

type_of_hash = str(input('Indicate the type of hash to crack ?')) # EXP : md5, SHA1, ETC
file_path = str(input('Enter path of the file: '))
hash_to_decrypt = str(input('Enter the hash to crack: '))

with open(file_path, 'r') as file:
    for line in file.readlines():
        if type_of_hash == 'md5':
            hash_object = hashlib.md5(line.strip().encode())
            hashed_word = hash_object.hexdigest()
            if hashed_word == hash_to_decrypt:
                print('HEY!!! NICE... Found MD5 Password: ' + line.strip())
                exit(0)

        if type_of_hash == 'sha1':
            hash_object = hashlib.sha1(line.strip().encode())
            hashed_word = hash_object.hexdigest()
            if hashed_word == hash_to_decrypt:
                print('HEY!!! NICE... Found SHA1 Password: ' + line.strip())
                exit(0)

    print('HEY, Try Again, Password Not In File.')