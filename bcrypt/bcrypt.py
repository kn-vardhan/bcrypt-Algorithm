import secrets
import sys
from . import blowfish
from . import data

# the cost value used for iterating and making strong hashing
# cost = log2(Iterations)
cost = 3


# function which generates a random salt of 16 Bytes = 128 bits
# this salt is added to the actual password and then hashed
# this method ensures to be effective against rainbow-table attacks
def generate_salt():

    salt = secrets.randbits(128)
    salt_str = bin(salt).replace('0b', '')
    salt_L = salt_str[:64]
    salt_R = salt_str[64:]
    salt_L = int(salt_L, 2)
    salt_R = int(salt_R, 2)
    
    return salt, salt_L, salt_R
    

# encodes the password to UTF-8
# and divides into arrays of small bytes, upto a total of 72 bytes = 572 bits
def convert_pwd(password):

    passwordBIN = bin(int(password)).replace('0b', '')
    start = 0
    PASS = []
    for i in range(len(passwordBIN)):
        if len(passwordBIN[start:i]) == 32:
            PASS.append(passwordBIN[start:i])
            start = i
    PASS.append(passwordBIN[start:])
    PASS = [int(str(i), 2) for i in PASS]
    L = len(PASS)
    
    return PASS, L


# encrypts a block using usual Blowfish technique and changes the state continuously
# XORs the block and state values with the salt, while splitting the salt into 32 bit arrays
def expand_key(password, salt, P_array, S_box):

    PASS, L = convert_pwd(password)
    for i in range(len(P_array)):
        P_array[i] = P_array[i] ^ int(PASS[i % L])
    
    if salt != 0:
        S_L = int(bin(salt).replace('0b', '')[:64], 2)
        S_R = int(bin(salt).replace('0b', '')[64:], 2)
    else:
        S_L = S_R = 0

    block = 0
    for i in range(8):
        
        if i % 2 == 0:
            block = block ^ int(S_L)
        else:
            block = block ^ int(S_R)
        block = blowfish.encrypt(block, P_array, S_box)
        halfBlock = bin(block).replace('0b', '')
        halfBlock_L = int(str(halfBlock[:32]), 2)
        halfBlock_R = int(str(halfBlock[32:]), 2)
        P_array[2*i] = halfBlock_L
        P_array[2*i + 1] = halfBlock_R
    
    SBIN = bin(salt).replace('0b', '')
    start = 0
    S_XOR = []
    for i in range(len(SBIN)):
        if len(SBIN[start:i]) == 64:
            S_XOR.append(SBIN[start:i])
            start = i
    S_XOR.append(SBIN[start:])
    S_XOR = [int(str(i), 2) for i in S_XOR]
    L = len(S_XOR)
    
    for i in range(4):
        for n in range(128):
            block = block ^ S_XOR[(n + 1) % L]
            block = blowfish.encrypt(block, P_array, S_box)
            halfBlock = bin(block).replace('0b', '')
            halfBlock_L = int(str(halfBlock[:32]), 2)
            halfBlock_R = int(str(halfBlock[32:]), 2)
            S_box[i][2*n] = halfBlock_L
            S_box[i][2*n + 1] = halfBlock_R
        
    return P_array, S_box, salt


# EKsBlowfish is the modification of the actual Blowsfish encryption
# the usual key setup in blowfish is replaced with an expensive key setup
# both salt and password are used to set subkeys
# alternative usage of salt and password while setting subkeys
# a total of 2^cost rounds are run
def EksBlowfish(password, salt, cost):

    P_array = data.P_array
    S_box = data.S_box
    
    new_P_array, new_S_box, _ = expand_key(password, salt, P_array, S_box)
    
    for i in range(pow(2, cost)):
        new_P_array, new_S_box, _ = expand_key(password, 0, new_P_array, new_S_box)
        new_P_array, new_S_box, _ = expand_key(salt, 0, new_P_array, new_S_box)
    
    return new_P_array, new_S_box, password, salt, cost
    

# the password is hashed using the last returned state
# the hashed password in bcrypt have a certain format
# hash = $2<a/b/x/y>$[cost]$[22 character salt][31 character hash]
def hash_pwd(password, salt, cost):
    
    hash = '$2b$'
    hash += '0' + str(cost) + '$'
    special = [i for i in range(33, 127)]

    password = ''.join(str(ord(x)) for x in password)
    P_array, S_box, _, _, _ = EksBlowfish(password, salt, cost)

    PASS, L = convert_pwd(password)
    ctext = PASS[0]
    for i in range(len(PASS)):
        ctext = blowfish.encrypt(ctext, P_array, S_box)
    
    start = 0
    salt = str(salt)
    i = 2
    while i < len(salt):
        if int(salt[start:i]) in special:
            hash += chr(int(salt[start:i]))
            start = i - 1
        elif int(salt[start:i+1]) in special:
            hash += chr(int(salt[start:i+1]))
            start = i
            i += 1
        else:
            hash += salt[start:i]
            start = i - 1
        i += 1
    
    start = 0
    ctext = str(ctext)
    i = 2
    while i < len(ctext):
        if int(ctext[start:i]) in special:
            hash += chr(int(ctext[start:i]))
            start = i - 1
        elif int(ctext[start:i+1]) in special:
            hash += chr(int(ctext[start:i+1]))
            start = i
            i += 1
        else:
            hash += ctext[start:i]
            start = i - 1
            i += 1
    
    return hash


if __name__ == '__main__':
    
    temp = input("Enter some text: ")

    Salt, Salt_Left, Salt_Right = generate_salt()
    while not Salt_Left:
        Salt, Salt_Left, Salt_Right = generate_salt()


    hash_pwd(temp, Salt, cost)
