# Secure Password Hashing
 
bcrypt is a password hashing algorithm based on Blowfish Block Cipher. The bcrypt function is the default password hash algorithm for [OpenBSD](https://en.wikipedia.org/wiki/OpenBSD) and default in some of the Linux distributions.

Here is a naive implementation of bcrypt hashing algorithm. bcrypt using an expensive key schedule rather than a usual key used in Blowfish encryptions. Theoritically, the expensive key has same security as a usual key but since the process is arbitrarily slow, it's helps deter brute-force attacks and rainbow-table attacks.

The database used above stores the usernames and the hashed password (not plain-text) along with the random salt values. You can play around with different usernames and passwords and check the hashed passwords for the secureness. 

The usual bcrypt hashed password looks as <br><b>E.g.</b> `$2<a/b/x/y>$[cost]$[22 character salt][31 character hash]`<br>
Where
- `$2<.>$`: The hash algorithm identifier (bcrypt)
- `cost`: Input cost (if cost = 10 $\Rightarrow$ $2^{10} = 1024$ rounds of key setups)
- `[22 character salt]`: A radix-64 encoding of the randomnly generated salt
- `[31 character hash]`: A radix-64 encoding of the first 23 bytes of the computed 24 byte hash from the user's password

Requirements - Python 3.8+, install DB Browser for SQLite <br>
Open your terminal or Commnad Prompt and run, <b> python3 LoginPortal.py </b> <br>
And follow the instructions as said by the program

> To view your hashed password, open the <b> user-database.db </b> file. 

#### NOTE: The passwords are never saved and only the hashed version of the password will be stored in the Database <br> This is a one-way function. The passwords can be converted to hashed password but not vice-versa
