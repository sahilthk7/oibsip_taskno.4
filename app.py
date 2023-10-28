from flask import Flask, render_template, request, redirect, url_for, session
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

users = {}

def register(username, password):
    hashed_password = sha256_crypt.encrypt(password)
    users[username] = hashed_password

def verify_password(username, password):
    stored_password = users.get(username)
    if stored_password:
        return sha256_crypt.verify(password, stored_password)
    return False

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        register(username, password)
        return redirect(url_for('login_page'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if verify_password(username, password):
            session['username'] = username
            return redirect(url_for('secured_page'))
    return render_template('login.html')

@app.route('/secured')
def secured_page():
    if 'username' in session:
        return render_template('secured.html', username=session['username'])
    return 'You need to log in to access this page.'

if __name__ == '__main__':
    app.run(debug=True)
