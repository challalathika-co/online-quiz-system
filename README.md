from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a real secret key in production

# In-memory "database" (replace with real DB in production)
users_db = {}

@app.route('/')
def home():
    if 'user' in session:
        return f"Hello, {session['user']}! You are logged in as a {session['role']}."
    return 'Welcome! <a href="/login">Login</a> or <a href="/signup">Sign Up</a>'

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if username in users_db:
            flash('Username already exists!')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        users_db[username] = {'password': hashed_password, 'role': role}
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))

    return '''
        <h2>Sign Up</h2>
        <form method="POST">
            Username: <input name="username" required><br>
            Password: <input name="password" type="password" required><br>
            Role: 
            <select name="role">
                <option value="student">Student</option>
                <option value="teacher">Teacher</option>
            </select><br>
            <input type="submit" value="Sign Up">
        </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users_db.get(username)
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            session['role'] = user['role']
            flash('Logged in successfully!')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login'))

    return '''
        <h2>Login</h2>
        <form method="POST">
            Username: <input name="username" required><br>
            Password: <input name="password" type="password" required><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a real secret key in production

# In-memory "database" (replace with real DB in production)
users_db = {}

@app.route('/')
def home():
    if 'user' in session:
        return f"Hello, {session['user']}! You are logged in as a {session['role']}."
    return 'Welcome! <a href="/login">Login</a> or <a href="/signup">Sign Up</a>'

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if username in users_db:
            flash('Username already exists!')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        users_db[username] = {'password': hashed_password, 'role': role}
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))

    return '''
        <h2>Sign Up</h2>
        <form method="POST">
            Username: <input name="username" required><br>
            Password: <input name="password" type="password" required><br>
            Role: 
            <select name="role">
                <option value="student">Student</option>
                <option value="teacher">Teacher</option>
            </select><br>
            <input type="submit" value="Sign Up">
        </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users_db.get(username)
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            session['role'] = user['role']
            flash('Logged in successfully!')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login'))

    return '''
        <h2>Login</h2>
        <form method="POST">
            Username: <input name="username" required><br>
            Password: <input name="password" type="password" required><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
