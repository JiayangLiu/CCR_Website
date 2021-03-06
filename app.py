from flask import Flask, render_template, flash, redirect, url_for, session, request, logging, send_from_directory, make_response, send_file
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import os
import time
from werkzeug.utils import secure_filename

app = Flask(__name__)
app._static_folder = '/Users/macdowell/Desktop/CCR_Website/download_models'

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'Flask_CCR'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MYSQL
mysql = MySQL(app)

@app.route('/')
def index():
	return render_template('home.html')

# Check if user logged in (use Flask Decorator)
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

class RegisterForm(Form):
	name = StringField('Name', [validators.Length(min=1, max=50)])
	username = StringField('Username', [validators.Length(min=4, max=25)])
	email = StringField('Email', [validators.Length(min=6, max=50)])
	password = PasswordField('Password', [
		validators.DataRequired(),
		validators.EqualTo('confirm', message='Passwords do not match.')
	])
	confirm = PasswordField('Confirm Password')

# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        # Create cursor
        cur = mysql.connection.cursor()
        # Execute query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))
        # Commit to DB
        mysql.connection.commit()
        # Close connection
        cur.close()
        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']
        # Create cursor
        cur = mysql.connection.cursor()
        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])
        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']
            user_id = data['id']
            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username
                session['user_id'] = user_id
                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)
    return render_template('login.html')

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Create cursor
    cur = mysql.connection.cursor()
    # Execute query,get upload codes records
    user_id = session['user_id']
    result = cur.execute("SELECT * FROM codes WHERE user_id = %s ORDER BY upload_date DESC",str(user_id))
    # result = cur.execute("SELECT * FROM codes")
    codes = cur.fetchall()

    if result>0:
        return render_template('dashboard.html',codes=codes)
    else:
        msg='No Codes Found'
        return render_template('dashboard.html',msg=msg)
    # Close connection
    cur.close()

# ==========================================================

@app.route('/download')
def download():
	return render_template('download.html')

@app.route('/download_models')
@is_logged_in
def download_models():
	response = make_response(send_file("download_models/CCR_Model_7.zip"))
	response.headers["Content-Disposition"] = "attachment; filename=download_models/CCR_Model_7.zip;"
	return response

# ==========================================================

@app.route('/upload')
def upload():
	return render_template('upload.html')

@app.route('/upload_codes', methods=['POST', 'GET'])
@is_logged_in
def upload_codes():
    if request.method == 'POST':
        # 1 upload file into server directory
        f = request.files['file']
        if f.filename == '':
            error = 'No file selected when upload'
            return render_template('upload.html', error=error)
        basepath = os.path.dirname(__file__)
        current_time = str(time.time())
        new_file_name = str(session['user_id']) + '_' + current_time[0:current_time.rfind('.',1)] + secure_filename(f.filename)[-4:]
        upload_path = os.path.join(basepath, 'files', new_file_name)
        f.save(upload_path)

        # 2 record the file in batabase
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO codes(filename, path, user_id) VALUES(%s, %s, %s)", (f.filename, upload_path, session['user_id']))
        mysql.connection.commit()
        cur.close()

        flash('You have successfully upload your codes', 'success')
    return redirect(url_for('dashboard'))

# ==========================================================

@app.route('/rank')
def rank():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT codes.id,codes.filename,codes.accuracy,codes.run_time,users.username,codes.upload_date FROM codes,users WHERE codes.accuracy!=0 AND codes.user_id = users.id ORDER BY codes.accuracy DESC")
    ranked_codes = cur.fetchall()
    return render_template('rank.html', ranked_codes = ranked_codes)


if __name__ == '__main__':
	app.secret_key = 'secret123'
	app.run(debug = True)
