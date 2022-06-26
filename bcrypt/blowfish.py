import random
import secrets
import sys
from .data import *


# generate a key of random bit length between 32 and 448 bits
def generate_key():
    
    key_length = random.randint(192, 430)
    key = secrets.randbits(key_length)
    keys = []

    while key_length >= 32:
        temp = secrets.randbits(32)
        _ = bin(temp).replace('0b', '')
        while len(_) != 32:
            temp = secrets.randbits(32)
            _ = bin(temp).replace('0b', '')
        keys.append(temp)
        key_length -= 32
    keys.append(secrets.randbits(key_length))
    
    bits = 0
    for k in keys:
        temp = bin(k).replace('0b', '')
        bits += len(temp)
    
    return keys, bits, len(keys)


# key expansion converts a key of at most 448 bits into several sub key arrays
def split_key(key):
    if int(key).bit_length() < 32 or int(key).bit_length() > 448:
        sys.exit("ERROR: Invalid key...\nTerminating the program")

    keys = []
    start = 0
    for i in range(1, len(key)):
        if int(key[start:i]).bit_length() == 32:
            keys.append(int(key[start:i]))
            start = i
    
    keys.append(int(key[start:]))
    return keys, len(keys)


# the F-Function splits input into 4 8-bit quarters
# and performs XOR, ADD operations
def function(L, S_box):
    
    string = ''
    for i in range(31, -1, -1):
        cur = (L >> i) & 1
        string += str(cur)
    
    a = int(string[:8], 2)
    b = int(string[8:16], 2)
    c = int(string[16:24], 2)
    d = int(string[24:], 2)
    
    to_R = S_box[0][a]
    to_R = (to_R + S_box[1][b]) % pow(2, 32)
    to_R ^= S_box[2][c]
    to_R = (to_R + S_box[3][d]) % pow(2, 32)
    
    return to_R


# data encryption occurs via 16 round feistel network
def encrypt(message, P_array, S_box):
    if message.bit_length() > 64:
        print(message.bit_length())
        sys.stdout.write("Input longer than 64-bit\n")
        exit()
    L = message // pow(2, 32)
    R = message & 0xffffffff
    for i in range(16):
        L = L ^ P_array[i]
        L1 = function(L, S_box)
        R = L1 ^ R
        L, R = R, L

    L, R = R, L
    L = L ^ P_array[17]
    R = R ^ P_array[16]
    encrypted = (L << 32) ^ R

    return encrypted


# decryption is exactly reverse of encryption in the fiestel network
def decrypt():
    try:
        message = input("Enter the text that is to be decrypted: ")
        message = int(message)
        key = input("Enter the key: ")
        
        final_key, length = split_key(key)
        for i in range(len(P_array)):
            P_array[i] = P_array[i] ^ final_key[i % length]
        
        L = message // pow(2, 32)
        R = message & 0xffffffff
        for i in range(17, 1, -1):
            L = L ^ P_array[i]
            L1 = function(L, S_box)
            R = L1 ^ R
            L, R = R, L
        
        L, R = R, L
        L = L ^ P_array[0]
        R = R ^ P_array[1]
        decrypted = (L << 32) ^ R
        sys.stdout.write("Message decryption successful\n")
        sys.stdout.write("The Decrypted message is: \n")
        print(decrypted)
    except:
        sys.exit("ERROR: Decryption failed...\nTerminating the program")


if __name__ == '__main__':

    sys.stdout.write("For Encrypting the message Press e/E\n")
    sys.stdout.write("For Decrypting the message Press d/D\n")
    operation = input("Press any key to perform action: ").upper()
    if operation == 'E':
        key, bit, length = generate_key()
        for i in range(len(P_array)):
            P_array[i] = P_array[i] ^ key[i % length]
        sys.stdout.write("Blowfish Algorithm takes only numbers as inputs\n")
        message = input("Enter the message that is to be encrypted: ")
        if int(message).bit_length() >= 64:
            sys.stdout.write("Input longer than 64-bit\n")
            exit()
        if not message.isdigit():
            sys.stdout.write("INPUT ERROR: Blowfish takes only numbers as input...")
            sys.stdout.write("Terminating Program\n")
            exit()
        cipher = encrypt(int(message), P_array, S_box)
        sys.stdout.write("Message encryption successful\n")
        sys.stdout.write("The Encrypted message is: \n")
        print(cipher)
        sys.stdout.write("Generated Key: ")
        print(*key, sep='')

    elif operation == 'D':
        decrypt()
    else:
        sys.exit("\nERROR: Wrong input...\nTerminating the program")

