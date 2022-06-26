import bcrypt.bcrypt as bcrypt
import database as db
import RandomPassword
import warnings


warnings.filterwarnings('ignore')
cost = bcrypt.cost

print("\n\t\t*** SECURE PASSWORD HASHING ALGORITHM ***\n")

print("Enter 0 to Sign Up")
print("Enter 1 to Log In")

sign = input("Enter key to perform action: ")

while sign != '0' and sign != '1':
    print("Invalid key...Try Again")
    sign = input("Enter key to perform action: ")

if sign == '0':
    print("You are currently in the Sign Up Portal")

    name = input("Create Username: ")
    db.cursor.execute('SELECT * from Users WHERE username=?', (name,))
    row_data = db.cursor.fetchall()
    name_flag = RandomPassword.UserVerifier(name)

    while row_data or not name_flag:
        if row_data:
            print("ERROR: Username already exists...Try another one")
            name = input("Create Username: ")
            db.cursor.execute('SELECT * from Users WHERE username=?', (name,))
            row_data = db.cursor.fetchall()
            name_flag = RandomPassword.UserVerifier(name)
        if not name_flag:
            print("ERROR: Username cannot have white spaces...Try another one")
            name = input("Create Username: ")
            db.cursor.execute('SELECT * from Users WHERE username=?', (name,))
            row_data = db.cursor.fetchall()
            name_flag = RandomPassword.UserVerifier(name)

    password = RandomPassword.AskUser()
    if password is None:
        password = input("Create Password: ")
        flag = RandomPassword.Verifier(password)

        while not flag:
            print(
                "Password should contain at-least 1 UpperCase Letter, 1 LowerCase Letter, 1 Digit, 1 Special Character")
            print("Minimum length of the password should be 8 and maximum 32")
            password = input("Create Password: ")
            flag = RandomPassword.Verifier(password)
        confirm = input("Confirm Password: ")

        while confirm != password:
            print("ERROR: The two passwords don't match")
            password = input("Create Password: ")
            flag = RandomPassword.Verifier(password)
            while not flag:
                print(
                    "Password should contain at-least 1 UpperCase Letter, 1 LowerCase Letter, 1 Digit, 1 Special Character")
                print("Minimum length of the password should be 8 and maximum 32")
                password = input("Create Password: ")
                flag = RandomPassword.Verifier(password)
            confirm = input("Confirm Password: ")

    else:
        print(f'Generated Password: {password}')
    
    Salt, Salt_Left, Salt_Right = bcrypt.generate_salt()
    while not Salt_Left:
        Salt, Salt_Left, Salt_Right = generate_salt()

    hashed = bcrypt.hash_pwd(password, Salt, cost)

    db.cursor.execute('INSERT INTO Users (username, hash, salt) VALUES (?, ?, ?)', (name, hashed, str(Salt)))
    db.connection.commit()
    print("\nUser created Successfully!")

elif sign == '1':
    print("You are currently in the Log In Portal")

    name = input("Enter Username: ")
    db.cursor.execute('SELECT * from Users WHERE username=?', (name,))
    row_data = db.cursor.fetchall()
    while not row_data:
        print("ERROR: Username doesn't exist...Try Again")
        name = input("Enter Username: ")
        db.cursor.execute('SELECT * from Users WHERE username=?', (name,))
        row_data = db.cursor.fetchall()
    PASS = input("Enter Password: ")
    Salt = int(row_data[0][2])
    hash = row_data[0][1]
    hashed = bcrypt.hash_pwd(PASS, Salt, cost)
    
    if hash != hashed:
        print("Incorrect Password...Terminating Program")
        db.cursor.close()
        db.connection.close()
        exit()

    print("Login Successful!\n")

    print("Enter 1 to Change Username")
    print("Enter 2 to Delete Account")
    print("Enter 3 to Log Out & Exit Program")
    _sign = input("Enter key to perform action: ")

    while _sign != '1' and _sign != '2' and _sign != '3':
        print("Invalid key...Try Again")
        _sign = input("Enter key to perform action: ")

    if _sign == '1':
        print("You are current in the Change Username Portal")
        
        new_name = input("Create New Username: ")
        new_name_flag = RandomPassword.UserVerifier(new_name)

        while not new_name_flag:
            print("ERROR: Username cannot have white spaces...Try another one")
            new_name = input("Create New Username: ")
            new_name_flag = RandomPassword.UserVerifier(new_name)
        db.cursor.execute('SELECT * from Users WHERE username=?', (new_name,))
        row_data = db.cursor.fetchall()

        while row_data:
            print("ERROR: Username already exists...Try another one")
            new_name = input("Create New Username: ")
            new_name_flag = RandomPassword.UserVerifier(new_name)
            while not new_name_flag:
                print("ERROR: Username cannot have white spaces...Try another one")
                new_name = input("Create New Username: ")
                new_name_flag = RandomPassword.UserVerifier(new_name)
            db.cursor.execute('SELECT * from Users WHERE username=?', (new_name,))
            row_data = db.cursor.fetchall()
        confirm_name = input("Confirm New Username: ")

        while confirm_name != new_name:
            print("ERROR: The two usernames don't match")
            new_name = input("Create New Username: ")
            new_name_flag = RandomPassword.UserVerifier(new_name)
            while not new_name_flag:
                print("ERROR: Username cannot have white spaces...Try another one")
                new_name = input("Create New Username: ")
                new_name_flag = RandomPassword.UserVerifier(new_name)
            confirm_name = input("Confirm New Username: ")
        
        db.cursor.execute('UPDATE Users SET username=? WHERE username=?', (new_name, name))
        db.connection.commit()
        print("\nUsername Changed Successful!...Terminating Program")

    elif _sign == '2':
        print("You are currently in the Delete Account Portal")
        
        confirm = input("Are you sure you want to delete your user id (Y/N): ").upper()
        while confirm != 'Y' and confirm != 'N':
            print("Invalid key...Try Again")
            confirm = input("Are you sure you want to delete your user id (Y/N): ").upper()
        if confirm == 'Y':
            db.cursor.execute('DELETE FROM Users WHERE username=?', (name,))
            db.connection.commit()
            print("\nSuccessfully Deleted Account...Terminating Program")
        elif confirm == 'N':
            print("\nAccount Deletion Unsuccessful...Terminating Program")

    elif _sign == '3':
        print("\nSuccessfully Logged Out...Terminating Program")

db.cursor.close()
db.connection.close()

'''
    if _sign == '0':
        print("You are currently in the Change Password Portal")
        password = input("Create New Password: ")
        flag = RandomPassword.Verifier(password)
        while not flag:
            print(
                "Password should contain at-least 1 UpperCase Letter, 1 LowerCase Letter, 1 Digit, 1 Special Character")
            print("Minimum length of the password should be 8 and maximum 32")
            password = input("Create New Password: ")
            flag = RandomPassword.Verifier(password)
        confirm = input("Confirm New Password: ")
        while confirm != password:
            print("ERROR: The two passwords don't match")
            confirm = input("Confirm New Password: ")

        Salt, Salt_Left, Salt_Right = bcrypt.generate_salt()
        while not Salt_Left:
            Salt, Salt_Left, Salt_Right = generate_salt()

        hashed = bcrypt.hash_pwd(password, Salt, cost)
        print(hash)
        print(hashed)
        db.cursor.execute('UPDATE Users SET hash=?, salt=? WHERE username=?', (hashed, str(Salt), name,))
        db.connection.commit()
        print("\nPassword Change Successful!...Terminating Program")
    
'''
