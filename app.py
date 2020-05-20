from flask import Flask, render_template, request, flash, url_for, redirect
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, DataRequired, EqualTo
from passlib.hash import sha256_crypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


#pip uninstall flask-bootstrap
#pip install Bootstrap-Flask
#pip install email_validator
#pip install WTForms
#pip install Flask-WTF
#pip install passlib
#pip install Flask-SQLAlchemy
#pip install flask-login

#sqlite3 database.db
#.tables to see the table User
#select * from user; to see all the users in the user table
#delete from user; to delete all the users in the user table
#.exit

#python3
#from app import db
#db.create_all()
#exit()


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite://///Users/ayushzenith/PycharmProjects/FlaskAPCSP/database.db"

Bootstrap(app)

db = SQLAlchemy(app)

loginmanager = LoginManager()
loginmanager.init_app(app)
loginmanager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(20), unique=False, nullable=False)
    lastname = db.Column(db.String(20), unique=False, nullable=False)
    username = db.Column(db.String(14), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80))


@loginmanager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=14)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=50)])
    remember = BooleanField('Remember Me')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=50),EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')
    firstname = StringField('First Name', validators=[InputRequired(), Length(min=1, max=20)])
    lastname = StringField('Last Name', validators=[InputRequired(), Length(min=1, max=20)])
    terms = BooleanField('I Agree to the Terms & Conditions', validators=[DataRequired()])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if current_user.is_authencticated():
            return redirect(url_for('index'))
    except:
        pass

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if sha256_crypt.verify(form.password.data, user.password):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('profile'))
            else:
                flash("Invalid password")

        else:
            flash("Username doesnt exist")
    return render_template('login.html', form = form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    try:
        if current_user.is_authencticated():
            return redirect(url_for('index'))
    except:
        pass

    form = RegisterForm()

    if form.validate_on_submit():
        try:
            user = User(firstname=form.firstname.data, lastname=form.lastname.data, username=form.username.data, email=form.email.data, password=sha256_crypt.encrypt(form.password.data))
            db.session.add(user)
            db.session.commit()
            flash('New user has been created!')
        except:
            flash('Username has already been taken')
    return render_template('signup.html', form = form)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username = current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
