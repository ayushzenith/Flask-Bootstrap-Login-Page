import os
from flask import Flask, render_template, request, flash, url_for, redirect
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, DataRequired, EqualTo
from passlib.hash import sha256_crypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, send, join_room, leave_room
import sqlite3


#pip uninstall flask-bootstrap
#pip install Bootstrap-Flask
#pip install email_validator
#pip install WTForms
#pip install Flask-WTF
#pip install passlib
#pip install Flask-SQLAlchemy
#pip install flask-login

#python3
#from app import db
#db.create_all()
#exit()

#sqlite3 user.db
#.tables to see the table User
#select * from user; to see all the users in the user table
#delete from user; to delete all the users in the user table
#DELETE FROM user WHERE id=3; to delete using id
#.exit


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////"+os.getcwd()+"/app.db"

Bootstrap(app)

socketio = SocketIO(app)
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

class chatrooms(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    roomid = db.Column(db.String(80), unique=True, nullable=False)
    usersonline = db.Column(db.Integer, unique=False, nullable=False)


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
            flash('Username or Email has already been taken')
    return render_template('signup.html', form = form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    return render_template('profile.html', username = current_user.username)

@app.route('/chathome')
@login_required
def chathome():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    sqlite_select_query = """SELECT * from chatrooms"""
    cursor.execute(sqlite_select_query)
    records = cursor.fetchall()
    temp = "<br><br> Current Chatrooms are(refresh page to update unfortunately i didnt have time to asyncronously update):<br><br>"
    for row in records:
        temp = temp + "Id: " + str(row[0]) + "\n<br>"
        temp = temp + "RoomId: " + str(row[1]) + "\n<br>"
        temp = temp + "\n<br>"
    return render_template("chatroom.html", sqlstuff = temp)

@app.route('/chathome/chat', methods=['GET', 'POST'])
@login_required
def chat():
    username = current_user.firstname + " \"" + current_user.username + "\" " + current_user.lastname
    room = request.args.get('room')
    try:
        roomid = chatrooms(roomid=room, usersonline=0)
        db.session.add(roomid)
        db.session.commit()
        print(room)
    except:
        print("not working")
        print(room)
    if username and room:
        return render_template('chat.html', username=username, room=room)
    else:
        return redirect(url_for('chathome'))

@socketio.on('send_message')
def handle_send_message_event(data):
    app.logger.info("{} has sent message to the room {}: {}".format(data['username'],data['room'],data['message']))
    socketio.emit('receive_message', data, room=data['room'])

@socketio.on('join_room')
def handle_join_room_event(data):
    try:
        x = chatrooms.query.filter_by(roomid=data['room']).first()
        if x:
            SQLAlchemy.update(chatrooms).where(chatrooms.roomid == data['room']).values(usersonline = x.usersonline + 1)
    except:
        print("sad")
    app.logger.info("{} has joined the room {}".format(data['username'], data['room']))
    join_room(data['room'])
    socketio.emit('join_room_announcement', data, room=data['room'])


@socketio.on('leave_room')
def handle_leave_room_event(data):
    app.logger.info("{} has left the room {}".format(data['username'], data['room']))
    leave_room(data['room'])
    socketio.emit('leave_room_announcement', data, room=data['room'])


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    socketio.run(app)
