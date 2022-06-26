import sqlite3
import warnings

warnings.filterwarnings('ignore')

# creates a database to store the usernames and hashed password
# the usernames are UNIQUE and direct password are never stored in the database

connection = sqlite3.connect('user-database.db')
cursor = connection.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS Users (username TEXT UNIQUE, hash TEXT, salt TEXT)''')

if __name__ == '__main__':
    cursor.close()
    connection.close()

