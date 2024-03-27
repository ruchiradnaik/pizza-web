from flask import Flask, render_template, request, redirect, url_for, session, flash,jsonify,redirect
from flask_mail import Mail, Message
import random
import string
import bcrypt
from flask_mysqldb import MySQL
import re 
import bleach


app = Flask(__name__)
app.static_folder = 'static'
app.secret_key = 'supersecretkey'  # Secret key for session

# Configuration for Flask-Mail
#simple mail transfer protocol
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Update with your SMTP server
app.config['MAIL_PORT'] = 587  # Update with your SMTP port
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ''  # Update with your email
app.config['MAIL_PASSWORD'] = ''  # Update with your email password
app.config['MAIL_DEFAULT_SENDER'] = ''  # Update with your email

#Update the mail_username and mail_default_sender with your so that the otps will be sent through your emails
#For the mail password you can add the original mail password but for safety and security of your email data

# MySQL Configuration
#enter your host name, user name, password and your database name
app.config['MYSQL_HOST'] = '' 
app.config['MYSQL_USER'] = ''
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = ''

mysql = MySQL(app)

mail = Mail(app)

# Function to generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=4))

# Function to validate email format
def validate_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+$'
    return re.match(regex, email)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if username is already in use
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users6 WHERE username = %s", (username,))
        existing_username = cur.fetchone()
        cur.close()

        if existing_username:
            # Username is already in use
            message = "Username is already in use. Please choose a different username."
            return render_template('signup.html', message=message)

        # Check if email is already in use
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users6 WHERE email = %s", (email,))
        existing_email = cur.fetchone()
        cur.close()

        if existing_email:
            # Email is already in use
            message = "Email is already in use. Please use a different email or log in if you already have an account."
            return render_template('signup.html', message=message)

        # Check if email is in proper format
        if not validate_email(email):
            message = "Invalid email format. Please enter a valid email address."
            return render_template('signup.html', message=message)
        
        # Check if password meets criteria
        if len(password) < 8 or any(c in '!@#$%^&*()_+' for c in password):
            message = "Password must be at least 8 characters long and contain only alphanumeric characters."
            return render_template('signup.html', message=message)
        
        otp = generate_otp()
        session['otp'] = otp

        # Send OTP via email
        msg = Message('OTP Verification', recipients=[email])
        msg.body = f'Your OTP for signup: {otp}'
        mail.send(msg)

        # Encrypt the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Convert hashed password to string for storage in the database
        hashed_password_str = hashed_password.decode('utf-8')
        
        # Insert user data into the database
        try:
            cur = mysql.connection.cursor()
            cur.execute('INSERT INTO users6 (username, email, password) VALUES (%s, %s, %s)', (username, email, hashed_password_str))
            mysql.connection.commit()
            cur.close()
        except Exception as e:
            print("An error occurred while inserting data into the database:", e)
        return redirect(url_for('verify'))

    # If GET request, display signup page
    return render_template('signup.html')

# Route for OTP verification
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        entered_otp = request.form['otp1'] + request.form['otp2'] + request.form['otp3'] + request.form['otp4'] 
        if session.get('otp') == entered_otp:
            # OTP verified, proceed to login
            session.pop('otp')  # Clear OTP from session
            return redirect(url_for('login'))
        else:
            message = "Invalid OTP. Please try again."
            return render_template('verify.html', message=message)
    return render_template('verify.html')
# Route for login page with option for existing users
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = bleach.clean(request.form['username'])
        password = bleach.clean(request.form['password'])

        if not username or not password:
            return "Username and password are required."

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users6 WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

      
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
               return redirect(url_for('pizza_site'))

        else:
            # Invalid username or password, display message
               return "Invalid username or password"
    
    
    # If GET request, display login page
    return render_template('login.html')


# Route for the pizza site
@app.route('/pizza')
def pizza_site():
    return render_template('pizza.html')


# Route for the root URL
@app.route('/')
def index():    
    return render_template('signup.html')


if __name__ == '__main__':
    app.secret_key = 'supersecretkey'  # Secret key for session
    app.run(debug=True)
