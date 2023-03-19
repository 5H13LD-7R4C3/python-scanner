from flask import render_template, flash, redirect, url_for
from app import app
from forms import LoginForm, RegistrationForm, ScanForm
from models import User, db

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', title='Home')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        return redirect(url_for('scan'))
    return render_template('login.html', title='Sign In', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    form = ScanForm()
    if form.validate_on_submit():
        # TODO: Implement scan functionality
        flash('Scan requested for IP Address: {}'.format(form.ip_address.data))
        return redirect(url_for('index'))
    return render_template('scan.html', title='Scan', form=form)
