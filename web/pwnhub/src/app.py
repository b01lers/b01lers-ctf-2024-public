from flask import render_template_string, Flask, request, render_template, redirect
from flask_login import LoginManager, current_user, login_required, login_user, logout_user, UserMixin
from hashlib import sha256
from random import getrandbits, choice
import string, enum

import threading
import time

INVALID = ["{{", "}}", ".", "_", "[", "]","\\", "x"]

app = Flask(__name__)
login_manager = LoginManager()
app.secret_key = hex(getrandbits(20))
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, name, password, verification, active=True):
        self.name = name
        self.password = password
        self.posts = []
        self.active = active
        self.verification = verification

    def is_active(self):
        return self.active
    
    def get_id(self):
        return self.name
    
    def is_authenticated(self):
        return True
    
class V(str, enum.Enum):
    user = 'user'
    admin = 'admin'

#Note: users are reset to this state every 5 minutes, please test on local :)
users = {
    "admin": User("admin", ''.join(choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(32)), V.admin),
    "pwnlyfans": User("pwnlyfans", ''.join(choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(32)), V.user)
}

@login_manager.user_loader
def user_loader(id):
    return users.get(id)

@app.before_first_request
def init_app():
    logout_user()

@app.post('/createpost', endpoint='createpost_post')
@login_required
def createpost():
    not None
    content = request.form.get('content')
    post_id = sha256((current_user.name+content).encode()).hexdigest()
    if any(char in content for char in INVALID):
        return render_template_string(f'1{"".join("33" for _ in range(len(content)))}7 detected' )
    current_user.posts.append({str(post_id): content})
    if len(content) > 20:
        return render_template('createpost.html', message=None, error='Content too long!', post=None)
    return render_template('createpost.html', message=f'Post successfully created, view it at /view/{post_id}', error=None)
    
@app.get('/createpost', endpoint='createpost_get')
@login_required
def createpost():
    return render_template('createpost.html', message=None, error=None, post=None)

@app.get('/view/<id>')
@login_required
def view(id):
    if (users[current_user.name].verification != V.admin):
        return render_template_string('This feature is still in development, please come back later.')
    content = next((post for post in current_user.posts if id in post), None)
    if not content:
        return render_template_string('Post not found')
    content = content.get(id, '')
    if any(char in content for char in INVALID):
        return render_template_string(f'1{"".join("33" for _ in range(len(content)))}7 detected')
    return render_template_string(f"Post contents here: {content[:250]}")

@app.get('/login',endpoint='login_get')
def login():
    return render_template('login.html')

@app.post('/login', endpoint='login_post')
def login():
    name = request.form.get('username')
    password = request.form.get('password')
    user = users.get(name)
    if user and user.password == password:
        login_user(user)
        return redirect('/home')
    return render_template('login.html', error='Invalid username or password')

@app.route('/')
def index():
    return render_template('home.html', user=None)

@app.route('/home')
@login_required
def home():
    return render_template('home.html', user=current_user)

@app.get('/register', endpoint='register_get')
def register():
    return render_template('register.html', error=None)

@app.post('/register', endpoint='register_post')
def register():
    name = request.form.get('username')
    password = request.form.get('password')
    if name in users:
        return render_template('register.html', error='User already exists')
    users[name] = User(name, password, V.user)
    return redirect('/login')

@app.route("/logout")
def logout():
    logout_user()
    return render_template('home.html', user=None)

#not shown on dist files -------
def execute_every_5_minutes():
    global users
    while True:

        users = {
            "admin": User("admin", ''.join(choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(32)), V.admin),
            "pwnlyfans": User("pwnlyfans", ''.join(choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(32)), V.user)
        }
        time.sleep(300) #reset once every 5 minutes to encourage people to test on local :)

thread = threading.Thread(target=execute_every_5_minutes)
thread.daemon = True
thread.start()
#not shown on dist files -------


if __name__ == '__main__':
    app.run(port=8000)