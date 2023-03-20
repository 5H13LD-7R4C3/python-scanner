import nmap
import sqlite3
import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from models import User,Scan, RegistrationForms,ScanForm
# Initialize Flask app
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'), static_folder=os.path.join(os.path.dirname(__file__), 'static'))

app.config.from_object(Config)

# Initialize Login Manager
login = LoginManager(app)
login.login_view = 'login'


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


if __name__ == '__main__':
    app.run()
