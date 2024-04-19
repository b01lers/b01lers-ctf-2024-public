import re
import string
import random
import hashlib
import sqlite3

def generate_random_printable_bytes(length):
    characters = string.printable
    return "".join([random.choice(characters) for i in range(length)]).encode()


sha256_regex = re.compile(r'^[a-fA-F0-9]{64}$')

def is_valid_sha256(hash_str):
    return bool(sha256_regex.match(hash_str))

def init_db():
    conn = sqlite3.connect("casino.db")
    cur = conn.cursor()
    admin_password = hashlib.sha256(b"hail_b01lershail_b01lershail_b01lershail_b01lershail_b01lers").hexdigest()
    cur.executescript("""
                      BEGIN;
                      DROP TABLE IF EXISTS casino;
                      CREATE TABLE casino(
                        id INTEGER PRIMARY KEY,
                        fullname TEXT,
                        username TEXT,
                        password TEXT,
                        balance INTEGER
                      );
                      COMMIT; """)
    # Add admin user, super rich, admin password
    cur.execute("INSERT INTO casino (fullname, username, password, balance) VALUES (?, ?, ?, ?)", ("Captain Baccarat", "admin", admin_password, 1000000))
    cur.execute("SELECT * FROM casino;")
    conn.commit()
    conn.close()

def register_user(fullname, username, password, balance=500):
    conn = sqlite3.connect("casino.db")
    cur = conn.cursor()
    # Check if username exists
    cur.execute("SELECT * FROM casino where username = ?", (username,))
    if (cur.fetchone()):
        raise Exception("Username already exists!")
    if (len(fullname) > 69):
        raise Exception("You trying to break Guiness record for longest name huh?")
    # Check the number of existing users
    cur.execute("SELECT COUNT(*) FROM casino")
    num_users = cur.fetchone()[0]
    if num_users >= 10:
        raise Exception("Private casino doesn't allow more than 10 people")
    # All good then, add stuff in
    cur.execute("INSERT INTO casino (fullname, username, password, balance) VALUES (?, ?, ?, ?)", (fullname, username, password, balance))
    conn.commit()

def check_db():
    conn = sqlite3.connect("casino.db")
    cur = conn.cursor()
    for row in cur.execute("SELECT * from casino"):
        print(row)
    conn.close()

def authenticate(username, password):
    conn = sqlite3.connect("casino.db")
    cur = conn.cursor()
    cur.execute("SELECT * from casino WHERE username = ? and password = ?", (username, password))
    if (cur.fetchone()):
        return True
    return False

def fetchScoreboard():
    conn = sqlite3.connect("casino.db")
    cur = conn.cursor()
    cur.execute("SELECT fullname, password, balance, username FROM casino")
    scoreboard = cur.fetchall()
    
    # Convert list of tuples to list of dictionaries
    scoreboard_dicts = []
    admin_password = ""
    for row in scoreboard:
        fullname = row[0]
        if row[3] == "admin":
            admin_password = row[1]
        scoreboard_dicts.append({
            'fullname': fullname,
            'password': row[1],
            'balance': row[2]
        })
    # Sorting list of dictionaries
    scoreboard_sorted = sorted(scoreboard_dicts, key=lambda x: (x['balance'], x['fullname'], x['password']), reverse=True)
    print(f"Admin password is {admin_password}")
    for i in range (len(scoreboard_sorted)):
        print(scoreboard_sorted[i])
        if scoreboard_sorted[i]['password'] == admin_password:
            scoreboard_sorted[i]['fullname'] = "The Real Captain Baccarat"
    return scoreboard_sorted

def updateBalance(username, amount):
    conn = sqlite3.connect("casino.db")
    cur = conn.cursor()
    
    # Get current amount
    cur.execute("SELECT balance from casino where username = ?", (username,))
    current_balance = cur.fetchone()[0]
    
    # Calculate new balance
    new_balance = max(0, current_balance + amount)
    
    # Update balance in the database
    cur.execute("UPDATE casino SET balance = ? WHERE username = ?", (new_balance, username))
    
    # Commit changes and close connection
    conn.commit()
    conn.close()

def checkBalance(username):
    conn = sqlite3.connect("casino.db")
    cur = conn.cursor()
    
    # Get current amount
    cur.execute("SELECT balance from casino where username = ?", (username,))
    current_balance = cur.fetchone()[0]
    return current_balance

def updatePassword(username, new_password):
    conn = sqlite3.connect("casino.db")
    cur = conn.cursor()
    # Get current amount
    cur.execute("UPDATE casino SET password = ? where username = ?", (new_password, username))
    conn.commit()
    conn.close()








