import random
import re
import sys

MAX = 32
MIN = 8
special = [i for i in range(33, 48)] + [i for i in range(58, 65)]
special += [i for i in range(91, 97)] + [i for i in range(123, 127)]


# function to verify whether the password is strong or not
# checks for uppercase, lowercase, digits and special characters
# returns a boolean value for strong password
def Verifier(password):

    special_chars = [chr(x) for x in special]
    count = 0
    for p in password:
        if p.isupper():
            count += 1
            break
    for p in password:
        if p.islower():
            count += 1
            break
    for p in password:
        if p.isdigit():
            count += 1
            break
    for p in password:
        if p in special_chars:
            count += 1
            break
    if 8 <= len(password) <= 32:
        count += 1
        
    return count == 5
    

# the username cannot have white spaces in it
# returns a boolean value for a valid username
def UserVerifier(user):
    
    flag = True
    x = re.findall(r'\s', user)
    if x:
        flag = False
    return flag


# function to ask user to generate random password or manual password
# if user prompts random, strong random password is generated
def AskUser():

    print("Enter 0 to manually create a password for the user")
    print("Enter 1 to generate a Random Password for the user")
    ask = input("Enter key: ")
    
    while ask != '0' and ask != '1':
        print("Invalid key...Try Again")
        ask = input("Enter key to perform action: ")

    if ask == '0':
        return
    elif ask == '1':
        pass_length = input("Enter the length of the password: ")
        while not pass_length.isdigit():
            print("ERROR: Length should be a digit...Try Again")
            pass_length = input("Enter the length of the password: ")
        pass_length = int(pass_length)
        return generate(pass_length)


# generates a strong random password with upper, lower, digit and special characters
# takes input from user which is the desired length of the password
def generate(size):

    pass_len = int(size)
    password = ''
    
    while pass_len < MIN or pass_len > MAX:
        if pass_len < MIN:
            sys.stdout.write("Password length should be minimum of 8 characters\n")
            pass_len = int(input("Enter the length of the password: "))
        elif pass_len > MAX:
            sys.stdout.write("Password length can be a maximum od 32 characters\n")
            pass_len = int(input("Enter the length of the password: "))
            pass_len = int(pass_len)

    password += chr(random.randint(48, 57))
    password += chr(random.randint(65, 90))
    password += chr(random.randint(97, 122))
    password += chr(random.choice(special))
    
    for i in range(pass_len - 4):
        password += chr(random.randint(33, 127))
    
    password = ''.join(str(x) for x in random.sample([i for i in password], pass_len))
    return password


if __name__ == '__main__':
    sys.stdout.write("RANDOM PASSWORD GENERATOR\n")
    length = int(input("Enter the length of the password: "))
    key = generate(length)
    sys.stdout.write(f"Password Generated: {key}\n")

