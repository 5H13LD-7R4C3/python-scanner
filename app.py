import nmap
import sqlite3
import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from datetime import datetime


from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo
# Initialize Flask app
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'), static_folder=os.path.join(os.path.dirname(__file__), 'static'))

app.config.from_object(Config)

# Initialize Login Manager
login = LoginManager(app)
login.login_view = 'login'
conn = sqlite3.connect('database.db') 
c = conn.cursor()

class Database:
    db_name = 'database.db'
    def __init__(self, db_name):
        self.db_name = db_name

    def create_tables(self):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        c.execute('''CREATE TABLE IF NOT EXISTS scans
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
             ip_address TEXT,
             port_number TEXT,
             report TEXT,
             scan_time TEXT,
             user_id INTEGER,
             FOREIGN KEY (user_id) REFERENCES users(id))''')

        c.execute('''CREATE TABLE IF NOT EXISTS users
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
             username TEXT UNIQUE,
             password TEXT)''')

        conn.commit()
        conn.close()

    def add_user(self, username, password):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))

        conn.commit()
        conn.close()

    def get_user(self, username):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        c.execute('SELECT * FROM users WHERE username=?', (username,))
        user = c.fetchone()

        conn.commit()
        conn.close()

        return user

    def add_scan(self, ip_address, port_number, report, scan_time, user_id):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        c.execute('INSERT INTO scans (ip_address, port_number, report, scan_time, user_id) VALUES (?, ?, ?, ?, ?)',
                  (ip_address, port_number, report, scan_time, user_id))

        conn.commit()
        conn.close()

    def get_scans_by_user(self, user_id):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        c.execute('SELECT * FROM scans WHERE user_id=?', (user_id,))
        scans = c.fetchall()

        conn.commit()
        conn.close()

        return scans

@login.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/')
def index():
    return render_template('index.html', title='Home')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data,
                    password_hash=generate_password_hash(form.password.data))
        user.save()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    form = ScanForm()
    if form.validate_on_submit():
        # Run nmap scan
        nm = nmap.PortScanner()
        scan_output = nm.scan(hosts=form.ip_address.data, arguments='-Pn -sS -p- -T4 --script vuln')
        # Save scan results to database
        scan = Scan(ip_address=form.ip_address.data, scan_output=str(scan_output))
        scan.save()
        flash('Scan successfully completed')
        return redirect(url_for('scan_list'))
    return render_template('scan.html', title='Scan', form=form)


@app.route('/scan_list')
@login_required
def scan_list():
    scans = Scan.query.all()
    return render_template('scan_list.html', title='Scan List', scans=scans)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    scans = db.relationship('Scan', backref='owner', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Scan {}>'.format(self.url)
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForms(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class ScanForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired()])
    submit = SubmitField('Scan')

if __name__ == '__main__':
    app.run()
