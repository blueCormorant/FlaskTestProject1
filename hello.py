from flask import Flask, render_template, session, redirect, \
	 url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, validators
from wtforms.validators import DataRequired
from password_strength import PasswordPolicy, PasswordStats


policy = PasswordPolicy.from_names(
	length=8,
	numbers=1,
	uppercase=2
)


class LoginForm(FlaskForm):
	username = StringField('Username', [validators.DataRequired()])
	password = StringField('Password', [validators.DataRequired()])
	submit = SubmitField('Submit')


app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to guess string'

bootstrap = Bootstrap(app)
moment = Moment(app)


def isValidPassword(password):

	stats = PasswordStats(password)

	if stats.length < 8:
		return False
	if stats.uppercase < 1:
		return False
	if stats.numbers < 1:
		return False
	
	return True

def flashPassword(password):

	stats = PasswordStats(password)

	if stats.length < 8:
		flash('Your password must be at least 8 characters long.')
	if stats.uppercase < 1:
		flash('Your password must have at least 1 uppercase character.')
	if stats.numbers < 1:
		flash('Your password must have at least 1 number.')

def passwordCheck(password):
	if isValidPassword(password):
		return True
	else:
		flashPassword(password)
		return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
	username = None
	password = None
	form = LoginForm()

	if form.validate_on_submit():
		username = form.username.data
		password = form.password.data		
		form.password.data = ''
		form.username.data = ''
		session['username'] = username
		checkPassword(password)	
		return redirect(url_for('login'))

	return render_template('login.html', form=form, username=session.get('username'), password=password)

@app.route('/comment')
def comment():
    return render_template('comment.html')

@app.route('/user/<name>')
def user(name):
    return render_template('user.html', name=name)

