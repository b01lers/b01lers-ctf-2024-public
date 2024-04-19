# Writeup for b01lers_casino by VinhChilling
Difficulty: Easy-Medium. 14 solves / 483 points

## Motivation
DEFCON is in Vegas. Yes you got that right.

## Analysis
The worst thing is that **hashing logic is client-side**. The backend only checks if it receives a valid SHA256 hash. For the slots machine, you can submit the score change to the backend as well. Note that you need a valid jwt token that last only 5 minutes. Also, you can change the password hash directly (note this).
```def create_token(username, secret):
    role = "noobs"
    if username == "admin":
        role = "admin"
    expire_time = int(time.time() + 300)
    jwt_token = jwt.encode({"username": username, "role": role, "expire_time": expire_time}, secret, algorithm="HS256")
    print(jwt_token)
    return jwt_token
```

Note that users can have the same *Fullname*, but the *username* has to be unique. This is an important point:
```def register_user(fullname, username, password, balance=500):
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
```

The key to solving the challenge lies in the /scoreboard endpoint:
```def fetchScoreboard():
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
```
The scoreboard is sorted by *balance*, *fullname* and then *password*. Also, although the admin's fullname is Captain Baccarat, "The Real Captain Baccarat" is displayed on the scoreboard. So if we have a user with the same Fullname and Balance, we can deduce the admin's hash character by character.
Optimally you can binary search for each character, but it's absolutely fine to check all characters.

## Solve script
Credit [Larry](https://github.com/SuperStormer). for the [script](https://github.com/b01lers/b01lers-ctf-2024/blob/main/web/b01lers_casino/solve/solve.py)

## Bottom line
A bit surprised with the number of solves. The script is a bit annoying to make, but the solution logic is quite simple in my opinion.
