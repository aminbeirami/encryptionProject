from lib.config import *
from flask import Flask, render_template, request, url_for, redirect, session, flash
from functools import wraps
from lib import functions as fcn


app = Flask(__name__)
app.secret_key = SECRET_KEY

def login_required(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if 'logged_in' in session:
            return f(*args,**kwargs)
        else:
            flash('you need to login first.')
            return redirect(url_for('login'))
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if is_admin():
            return f(*args,**kwargs)
        else:
            return redirect(url_for('permission_error'))
    return wrap

def session_initialization(isadmin,username):
    if isadmin == True:                               #if the user is admininstrator
        session['logged_in'] = True
        session['user'] = username
        session['role'] = 'admin'
    else:                                               #if the user is a regular user 
        session['logged_in'] = True           
        session['user'] = username
        session['role'] = 'user'
def session_kill():
    session.pop('logged_in',None)
    session.pop('user',None)
    session.pop('role',None)
    PROJECT_TITLE = None

def is_admin():
    role = session['role']
    if role =='admin':
        return True
    else:
        return False

''' Home '''

@app.route('/')
def index():
    return render_template('index.html')

''' Login Page '''

@app.route('/login', methods = ['POST','GET'])
def login():
    error = None
    session_kill()
    if request.method =='POST':
        username = request.form['username']
        password = request.form['password']
        result = fcn.fetch_username_and_password(username,password)
        if result[0] !=True:
            error = 'incorrect credentials'
        else:
            session_initialization(result[1],username)
    if 'logged_in' in session:
        if is_admin():
            return redirect(url_for('admin'))
        else:
            return redirect(url_for('receive_message'))
    else:
        return render_template('login.html', error = error)

''' the administrator's page '''

@app.route('/admin')
@login_required
@admin_required
def admin():
    return render_template('admin.html')

'''logout route '''

@app.route("/logout")
def logout():
    session_kill()
    flash('you are logged out successfully!')
    return redirect(url_for('login'))

'''create a user in system page '''

@app.route('/adduser', methods = ['GET','POST'])
@login_required
@admin_required
def define_user():
    if request.method == 'GET':
        return render_template('add_user.html')
    else:
        fcn.hashing_and_save(request.form.items())
        flash('User added successfuly!')
        return render_template('add_user.html')

@app.route('/sendMessage', methods = ['GET','POST'])
@login_required
@admin_required
def send_message():
    if request.method == 'GET':
        listOfUsers = fcn.fetch_users_username()
        return render_template('send_message.html', usernames = listOfUsers)
    else:
        fcn.sendMessage(request.form.items())
        flash('your message was sent successfully!')
        return redirect(url_for('send_message'))

@app.route('/receiveMessage')
@login_required
def receive_message():
    user = session['user']
    decryptedMessage = fcn.receive_messages(user)
    return render_template('receive_message.html',messages = decryptedMessage, user = user)

''' access denied page '''

@app.route('/permissionError')
def permission_error():
    return render_template("permission_error.html")

''' running the app '''

if __name__ == '__main__':
    app.debug = True
    app.run()