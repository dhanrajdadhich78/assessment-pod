from flask import Flask, g, request, render_template, flash, redirect, url_for, session, logging, send_file, jsonify, Response, render_template_string
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, DateTimeField, BooleanField, IntegerField, DecimalField, HiddenField, SelectField, RadioField, DateField
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from flask_mail import Mail, Message
from functools import wraps
from werkzeug.utils import secure_filename
from coolname import generate_slug
from datetime import timedelta, datetime
from objective import ObjectiveTest
from subjective import SubjectiveTest
from deepface import DeepFace
import pandas as pd
import stripe
import operator
import functools
import math, random
import csv
import nltk
import cv2
import numpy as np
import json
import base64
from wtforms_components import TimeField
from wtforms.validators import ValidationError, NumberRange
from flask_session import Session
from flask_cors import CORS
import camera
import os

nltk.download('punkt_tab')

# Initialize Flask App
app = Flask(__name__)

# Database Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PORT'] = 33060
app.config['MYSQL_PASSWORD'] = 'H@rH@rMahad3v'
app.config['MYSQL_DB'] = 'mkraftaiexam'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Email Configuration
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '16f646dd6d8eef'
app.config['MAIL_PASSWORD'] = 'bfe2378fb1ead8'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

# Stripe Configuration
stripe_keys = {
	"secret_key": "dummy",
	"publishable_key": "dummy",
}
stripe.api_key = stripe_keys["secret_key"]

# Session Configuration
app.config['SECRET_KEY'] = 'thisisdhanrajdadhichverylongsecratekeynumber123456789andsymbols!@#$%^&*()'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['CORS_HEADERS'] = 'Content-Type'
# app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_PERMANENT'] = True
app.config["TEMPLATES_AUTO_RELOAD"] = True

app.config['SESSION_FILE_DIR'] = './flask_session/'  # Ensure this directory is writable
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize Extensions
mail = Mail(app)
cors = CORS(app)
sess = Session()
sess.init_app(app)
mysql = MySQL(app)

# Other Settings
sender = 'dhanraj.dadhich@multiplierskraft.com'
YOUR_DOMAIN = 'http://localhost:5001'


# Session Management
@app.before_request
def make_session_permanent():
	session.permanent = True


# Decorators
def user_role_professor(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session and session.get('user_role') =="teacher":
			return f(*args, **kwargs)
		flash('You dont have privilege to access this page!', 'danger')
		return render_template("404.html") if 'logged_in' in session else redirect(url_for('login'))
	return wrap

def user_role_student(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		# Debug session data

		# Check if user is logged in and is a student
		if session.get('logged_in') and session.get('user_role') == "student":
			return f(*args, **kwargs)

		# Handle unauthorized access
		if session.get('logged_in'):
			flash('You don’t have the privilege to access this page!', 'danger')
			print("Access denied. Rendering 404.")
			return render_template("404.html")
		else:
			flash('Unauthorized, Please login!', 'danger')
			print("User not logged in. Redirecting to login.")
			return redirect(url_for('login'))
	return wrap


# Helper Function
def generateOTP():
	return str(random.randint(100000, 999999))

def examcreditscheck():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT examcredits from users where examcredits >= 1 and email = %s and uid = %s', (session.get('email'), session.get('uid')))
	if results > 0:
		return True
	return False

def examtypecheck(tidoption):
	cur = mysql.connection.cursor()
	cur.execute('SELECT test_type from teachers where test_id = %s and email = %s and uid = %s', (tidoption, session.get('email'), session.get('uid')))
	callresults = cur.fetchone()
	cur.close()
	return callresults if callresults else {'test_type': None}

def displaywinstudentslogs(testid, email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT * from window_estimation_log where test_id = %s and email = %s and window_event = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return callresults

def countwinstudentslogs(testid, email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT COUNT(*) as wincount from window_estimation_log where test_id = %s and email = %s and window_event = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return [i['wincount'] for i in callresults] if callresults else [0]

def countMobStudentslogs(testid, email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT COUNT(*) as mobcount from proctoring_log where test_id = %s and email = %s and phone_detection = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return [i['mobcount'] for i in callresults] if callresults else [0]

def countMTOPstudentslogs(testid, email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT COUNT(*) as percount from proctoring_log where test_id = %s and email = %s and person_status = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return [i['percount'] for i in callresults] if callresults else [0]

def countTotalstudentslogs(testid, email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT COUNT(*) as total from proctoring_log where test_id = %s and email = %s', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return [i['total'] for i in callresults] if callresults else [0]

def neg_marks(email, testid, negm):
	cur = mysql.connection.cursor()
	results = cur.execute(
		"select marks,q.qid as qid, q.ans as correct, ifnull(s.ans,0) as marked from questions q inner join students s on  s.test_id = q.test_id and s.test_id = %s and s.email = %s and s.qid = q.qid group by q.qid order by q.qid asc",
		(testid, email)
	)
	data = cur.fetchall()
	sum_marks = 0.0
	if data:
		for row in data:
			if str(row['marked']).upper() != '0':
				if str(row['marked']).upper() != str(row['correct']).upper():
					sum_marks -= (negm / 100) * int(row['marks'])
				elif str(row['marked']).upper() == str(row['correct']).upper():
					sum_marks += int(row['marks'])
	return sum_marks

def marks_calc(email, testid):
	cur = mysql.connection.cursor()
	results = cur.execute("select neg_marks from teachers where test_id=%s", [testid])
	results = cur.fetchone()
	negm = results['neg_marks'] if results else 0
	cur.close()
	return neg_marks(email, testid, negm)
# Forms Definitions

class QAUploadForm(FlaskForm):
	subject = StringField('Subject', validators=[validators.DataRequired()])
	topic = StringField('Topic', validators=[validators.DataRequired()])
	doc = FileField('CSV Upload', validators=[FileRequired()])
	start_date = DateField('Start Date', validators=[validators.DataRequired()])
	start_time = TimeField('Start Time', default=datetime.utcnow() + timedelta(hours=5.5), validators=[validators.DataRequired()])
	end_date = DateField('End Date', validators=[validators.DataRequired()])
	end_time = TimeField('End Time', default=datetime.utcnow() + timedelta(hours=5.5), validators=[validators.DataRequired()])
	duration = IntegerField('Duration(in min)', validators=[validators.DataRequired()])
	password = PasswordField('Exam Password', [validators.Length(min=3, max=6), validators.DataRequired()])
	proctor_type = RadioField('Proctoring Type', choices=[('0', 'Automatic Monitoring'), ('1', 'Live Monitoring')], validators=[validators.DataRequired()])

	def validate_end_date(form, field):
		if field.data < form.start_date.data:
			raise ValidationError("End date must not be earlier than start date.")

	def validate_end_time(form, field):
		start_date_time = datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		end_date_time = datetime.strptime(str(form.end_date.data) + " " + str(field.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		if start_date_time >= end_date_time:
			raise ValidationError("End date time must not be earlier/equal than start date time")

	def validate_start_date(form, field):
		if datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S") < datetime.now():
			raise ValidationError("Start date and time must not be earlier than current")

class UploadForm(FlaskForm):
	subject = StringField('Subject', validators=[validators.DataRequired()])
	topic = StringField('Topic', validators=[validators.DataRequired()])
	doc = FileField('CSV Upload', validators=[FileRequired()])
	start_date = DateField('Start Date', validators=[validators.DataRequired()])
	start_time = TimeField('Start Time', default=datetime.utcnow() + timedelta(hours=5.5), validators=[validators.DataRequired()])
	end_date = DateField('End Date', validators=[validators.DataRequired()])
	end_time = TimeField('End Time', default=datetime.utcnow() + timedelta(hours=5.5), validators=[validators.DataRequired()])
	calc = BooleanField('Enable Calculator', default=False)
	neg_mark = DecimalField('Enable negative marking in % ', validators=[NumberRange(min=0, max=100),validators.DataRequired()])
	duration = IntegerField('Duration(in min)', validators=[validators.DataRequired()])
	password = PasswordField('Exam Password', [validators.Length(min=3, max=6), validators.DataRequired()])
	proctor_type = RadioField('Proctoring Type', choices=[('0', 'Automatic Monitoring'), ('1', 'Live Monitoring')], validators=[validators.DataRequired()])

	def validate_end_date(form, field):
		if field.data < form.start_date.data:
			raise ValidationError("End date must not be earlier than start date.")

	def validate_end_time(form, field):
		start_date_time = datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		end_date_time = datetime.strptime(str(form.end_date.data) + " " + str(field.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		if start_date_time >= end_date_time:
			raise ValidationError("End date time must not be earlier/equal than start date time")

	def validate_start_date(form, field):
		if datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S") < datetime.now():
			raise ValidationError("Start date and time must not be earlier than current")

class PracUploadForm(FlaskForm):
	subject = StringField('Subject', validators=[validators.DataRequired()])
	topic = StringField('Topic', validators=[validators.DataRequired()])
	questionprac = StringField('Question', validators=[validators.DataRequired()])
	marksprac = IntegerField('Marks', validators=[validators.DataRequired()])
	start_date = DateField('Start Date', validators=[validators.DataRequired()])
	start_time = TimeField('Start Time', default=datetime.utcnow() + timedelta(hours=5.5), validators=[validators.DataRequired()])
	end_date = DateField('End Date', validators=[validators.DataRequired()])
	end_time = TimeField('End Time', default=datetime.utcnow() + timedelta(hours=5.5), validators=[validators.DataRequired()])
	duration = IntegerField('Duration(in min)', validators=[validators.DataRequired()])
	compiler = SelectField(u'Compiler/Interpreter', choices=[('11', 'C'), ('27', 'C#'), ('1', 'C++'), ('114', 'Go'), ('10', 'Java'),
															('47', 'Kotlin'), ('56', 'Node.js'), ('43', 'Objective-C'), ('29', 'PHP'),
															('54', 'Perl-6'), ('116', 'Python 3x'), ('117', 'R'), ('17', 'Ruby'),
															('93', 'Rust'), ('52', 'SQLite-queries'), ('40', 'SQLite-schema'),
															('39', 'Scala'), ('85', 'Swift'), ('57', 'TypeScript')], validators=[validators.DataRequired()])
	password = PasswordField('Exam Password', [validators.Length(min=3, max=10), validators.DataRequired()])
	proctor_type = RadioField('Proctoring Type', choices=[('0', 'Automatic Monitoring'), ('1', 'Live Monitoring')], validators=[validators.DataRequired()])

	def validate_end_date(form, field):
		if field.data < form.start_date.data:
			raise ValidationError("End date must not be earlier than start date.")

	def validate_end_time(form, field):
		start_date_time = datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		end_date_time = datetime.strptime(str(form.end_date.data) + " " + str(field.data),"%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
		if start_date_time >= end_date_time:
			raise ValidationError("End date time must not be earlier/equal than start date time")

	def validate_start_date(form, field):
		if datetime.strptime(str(form.start_date.data) + " " + str(form.start_time.data),"%Y-%m-%d %H:%M:%S") < datetime.now():
			raise ValidationError("Start date and time must not be earlier than current")

class TestForm(Form):
	test_id = StringField('Exam ID', validators=[validators.DataRequired()])
	password = PasswordField('Exam Password', validators=[validators.DataRequired()])
	img_hidden_form = HiddenField(label=(''), validators=[validators.DataRequired()])

# API Routes
@app.route("/config")
@user_role_professor
def get_publishable_key():
	stripe_config = {"publicKey": stripe_keys["publishable_key"]}
	return jsonify(stripe_config)

@app.route('/video_feed', methods=['POST'])
@user_role_student
def video_feed():
	imgData = request.form['data[imgData]']
	testid = request.form['data[testid]']
	voice_db = request.form['data[voice_db]']
	proctorData = camera.get_frame(imgData)
	jpg_as_text = proctorData['jpg_as_text']
	mob_status = proctorData['mob_status']
	person_status = proctorData['person_status']
	user_move1 = proctorData['user_move1']
	user_move2 = proctorData['user_move2']
	eye_movements = proctorData['eye_movements']
	cur = mysql.connection.cursor()
	results = cur.execute(
		'INSERT INTO proctoring_log (email, name, test_id, voice_db, img_log, user_movements_updown, user_movements_lr, user_movements_eyes, phone_detection, person_status, uid) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
		(session.get('email'), session.get('name'), testid, voice_db, jpg_as_text, user_move1, user_move2, eye_movements, mob_status, person_status,session.get('uid'))
	)
	mysql.connection.commit()
	cur.close()
	return "recorded image of video" if results else "error in video"

@app.route('/window_event', methods=['POST'])
@user_role_student
def window_event():
	testid = request.form['testid']
	cur = mysql.connection.cursor()
	results = cur.execute('INSERT INTO window_estimation_log (email, test_id, name, window_event, uid) values(%s,%s,%s,%s,%s)', (session.get('email'), testid, session.get('name'), 1, session.get('uid')))
	mysql.connection.commit()
	cur.close()
	return "recorded window" if results else "error in window"

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
	try:
		checkout_session = stripe.checkout.Session.create(
			payment_method_types=['card'],
			line_items=[
				{
					'price_data': {
						'currency': 'inr',
						'unit_amount': 499 * 100,
						'product_data': {
							'name': 'Basic Exam Plan of 10 units',
							'images': ['https://i.imgur.com/LsvO3kL_d.webp?maxwidth=760&fidelity=grand'],
						},
					},
					'quantity': 1,
				},
			],
			mode='payment',
			success_url=YOUR_DOMAIN + '/success',
			cancel_url=YOUR_DOMAIN + '/cancelled',
		)
		return jsonify({'id': checkout_session.id})
	except Exception as e:
		return jsonify(error=str(e)), 403

@app.route("/livemonitoringtid")
@user_role_professor
def livemonitoringtid():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT * from teachers where email = %s and uid = %s and proctoring_type = 1', (session.get('email'), session.get('uid')))
	cresults = cur.fetchall() if results > 0 else None
	now = datetime.now()
	testids = []
	if cresults:
		for a in cresults:
			if datetime.strptime(str(a['start']), "%Y-%m-%d %H:%M:%S") <= now and datetime.strptime(str(a['end']),
																									"%Y-%m-%d %H:%M:%S") >= now:
				testids.append(a['test_id'])
	cur.close()
	return render_template("livemonitoringtid.html", cresults=testids if testids else None)

@app.route('/live_monitoring', methods=['GET', 'POST'])
@user_role_professor
def live_monitoring():
	testid = request.form['choosetid'] if request.method == 'POST' else None
	return render_template('live_monitoring.html', testid=testid)

@app.route("/success")
@user_role_professor
def success():
	cur = mysql.connection.cursor()
	cur.execute('UPDATE users set examcredits = examcredits+10 where email = %s and uid = %s', (session.get('email'), session.get('uid')))
	mysql.connection.commit()
	cur.close()
	return render_template("success.html")

@app.route("/cancelled")
@user_role_professor
def cancelled():
	return render_template("cancelled.html")

@app.route("/payment")
@user_role_professor
def payment():
	cur = mysql.connection.cursor()
	cur.execute('SELECT examcredits FROM USERS where email = %s and uid = %s', (session.get('email'), session.get('uid')))
	callresults = cur.fetchone()
	cur.close()
	return render_template("payment.html", key=stripe_keys['publishable_key'], callresults=callresults)


# Basic Routes
@app.route('/')
def index():
	return render_template('index.html')

@app.errorhandler(404)
def not_found(e):
	return render_template("404.html")

@app.errorhandler(500)
def internal_error(error):
	return render_template("500.html")


@app.route('/calc')
def calc():
	return render_template('calc.html')

@app.route('/report_professor')
@user_role_professor
def report_professor():
	return render_template('report_professor.html')

@app.route('/student_index')
@user_role_student
def student_index():
	return render_template('student_index.html')

@app.route('/professor_index')
@user_role_professor
def professor_index():
	return render_template('professor_index.html')

@app.route('/faq')
def faq():
	return render_template('faq.html')

@app.route('/report_student')
@user_role_student
def report_student():
	return render_template('report_student.html')

@app.route('/report_professor_email', methods=['GET', 'POST'])
@user_role_professor
def report_professor_email():
	if request.method == 'POST':
		careEmail = "theblockchaincto@gmail.com"
		cname = session.get('name')
		cemail = session.get('email')
		ptype = request.form['prob_type']
		cquery = request.form['rquery']
		msg1 = Message('PROBLEM REPORTED', sender=sender, recipients=[careEmail])
		msg1.body = " ".join(["NAME:", cname, "PROBLEM TYPE:", ptype, "EMAIL:", cemail, "", "QUERY:", cquery])
		mail.send(msg1)
		flash('Your Problem has been recorded.', 'success')
	return render_template('report_professor.html')

@app.route('/report_student_email', methods=['GET', 'POST'])
@user_role_student
def report_student_email():
	if request.method == 'POST':
		careEmail = "theblockchaincto@gmail.com"
		cname = session.get('name')
		cemail = session.get('email')
		ptype = request.form['prob_type']
		cquery = request.form['rquery']
		msg1 = Message('PROBLEM REPORTED', sender=sender, recipients=[careEmail])
		msg1.body = " ".join(["NAME:", cname, "PROBLEM TYPE:", ptype, "EMAIL:", cemail, "", "QUERY:", cquery])
		mail.send(msg1)
		flash('Your Problem has been recorded.', 'success')
	return render_template('report_student.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
	if request.method == 'POST':
		careEmail = "theblockchaincto@gmail.com"
		cname = request.form['cname']
		cemail = request.form['cemail']
		cquery = request.form['cquery']
		msg1 = Message('Hello', sender=sender, recipients=[cemail])
		msg2 = Message('Hello', sender=sender, recipients=[careEmail])
		msg1.body = "YOUR QUERY WILL BE PROCESSED! WITHIN 24 HOURS"
		msg2.body = " ".join(["NAME:", cname, "EMAIL:", cemail, "QUERY:", cquery])
		mail.send(msg1)
		mail.send(msg2)
		flash('Your Query has been recorded.', 'success')
	return render_template('contact.html')

@app.route('/lostpassword', methods=['GET', 'POST'])
def lostpassword():
	if request.method == 'POST':
		lpemail = request.form['lpemail']
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT * from users where email = %s', [lpemail])
		if results > 0:
			sesOTPfp = generateOTP()
			session['tempOTPfp'] = sesOTPfp
			session['seslpemail'] = lpemail
			msg1 = Message('MKraft Capability Solutions LLP. - OTP Verification for Lost Password', sender=sender,
							recipients=[lpemail])
			msg1.body = "Your OTP Verfication code for reset password is " + sesOTPfp + "."
			mail.send(msg1)
			return redirect(url_for('verifyOTPfp'))
		else:
			return render_template('lostpassword.html', error="Account not found.")
	return render_template('lostpassword.html')

@app.route('/verifyOTPfp', methods=['GET', 'POST'])
def verifyOTPfp():
	if request.method == 'POST':
		fpOTP = request.form['fpotp']
		fpsOTP = session.get('tempOTPfp')
		if fpOTP == fpsOTP:
			return redirect(url_for('lpnewpwd'))
	return render_template('verifyOTPfp.html')

@app.route('/lpnewpwd', methods=['GET', 'POST'])
def lpnewpwd():
	if request.method == 'POST':
		npwd = request.form['npwd']
		cpwd = request.form['cpwd']
		slpemail = session.get('tempOTPfp')
		if npwd == cpwd:
			cur = mysql.connection.cursor()
			cur.execute('UPDATE users set password = %s where email = %s', (npwd, slpemail))
			mysql.connection.commit()
			cur.close()
			session.clear()
			return render_template('login.html', success="Your password was successfully changed.")
		else:
			return render_template('login.html', error="Password doesn't matched.")
	return render_template('lpnewpwd.html')

@app.route('/generate_test')
@user_role_professor
def generate_test():
	return render_template('generatetest.html')

@app.route('/changepassword_professor')
@user_role_professor
def changepassword_professor():
	return render_template('changepassword_professor.html')

@app.route('/changepassword_student')
@user_role_student
def changepassword_student():
	return render_template('changepassword_student.html')


# User Authentication Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		name = request.form.get('name', '').strip()
		email = request.form.get('email', '').strip()
		password = request.form.get('password', '').strip()
		user_type = request.form.get('user_type', '').strip()
		imgdata = request.form.get('image_hidden', '')

		if not all([name, email, password, user_type]):
			flash("All fields are required. Please fill in the missing information.", "danger")
			return render_template('register.html')
		cur = mysql.connection.cursor()
		cur.execute('SELECT * FROM users WHERE email = %s', [email])
		existing_user = cur.fetchone()
		if existing_user:
			flash("This email is already registered. Please log in or use a different email.", "danger")
			return redirect(url_for('login'))
		session['name'] = name
		session['email'] = email
		session['password'] = password
		session['user_type'] = user_type
		session['imgdata'] = imgdata

		otp = generateOTP()
		session['otp'] = otp
		try:
			msg = Message(
				subject='MKraft Capability Solutions LLP - OTP Verification',
				sender=app.config['MAIL_USERNAME'],
				recipients=[email]
			)
			msg.body = f"""Dear {name},
\nThank you for registering with MKraft Capability Solutions LLP.
\nTo complete your account creation process, please use the One-Time Password (OTP) below for verification:
\nYour OTP is: \b{otp}\b
\nThis OTP is valid for the next 10 minutes. \nPlease enter it on the verification page to proceed with your registration.
\bIf you did not initiate this registration, please disregard this email. Your account will remain secure.
\nIf you need assistance, feel free to contact our support team at support@mkraftsolutions.com.
\n\bBest regards,\b
\nThe MKraft Capability Solutions Team
			"""
			mail.send(msg)
			flash("An OTP has been sent to your email. Please check your inbox.", "success")
		except Exception as e:
			flash(f"An error occurred while sending the OTP: {str(e)}", "danger")
			return redirect(url_for('register'))
		# return redirect(url_for('verifyEmail', otp=otp, name=name, email=email, password=password, user_type=user_type))
		return redirect(url_for('verifyEmail'))

	return render_template('register.html')


@app.route('/verifyEmail', methods=['GET', 'POST'])
def verifyEmail():
	if request.method == 'POST':
		# otp = request.args.get('otp')
		# name = request.args.get('name')
		# email = request.args.get('email')
		# password = request.args.get('password')
		# user_type = request.args.get('user_type')
		otp = session.get('otp')
		name = session.get('name')
		email = session.get('email')
		password = session.get('password')
		user_type = session.get('user_type')
		imgdata = session.get('imgdata')

		user_folder = os.path.join('userdata', email)
		image_path = os.path.join(user_folder, 'profile_image.png')

		if os.path.exists(image_path):
			with open(image_path, 'rb') as f:
				imgdata = base64.b64encode(f.read()).decode('utf-8')
		else:
			imgdata = session.get('imgdata')

		entered_otp = request.form.get('eotp', '').strip()

		if not otp:
			flash("Session expired. Please register again.", "danger")
			return redirect(url_for('register'))
		if entered_otp == otp:
			try:
				cur = mysql.connection.cursor()
				cur.execute('''INSERT INTO users (name, email, password, user_type, user_image, user_login)
								VALUES (%s, %s, %s, %s, %s, %s)''',
							(name, email, password, user_type, imgdata, 0))
				mysql.connection.commit()
				cur.close()
				flash("Registration successful! You are now verified.", "success")
				session.clear()
				return redirect(url_for('login'))
			except Exception as e:
				flash(f"An error occurred during registration: {str(e)}", "danger")
				return redirect(url_for('register'))
		else:
			flash("The OTP you entered is incorrect. Please try again.", "danger")
			return render_template('verifyEmail.html')

	return render_template('verifyEmail.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		email = request.form['email']
		password_candidate = request.form['password']
		user_type = request.form['user_type']
		imgdata1 = request.form['image_hidden']
		cur = mysql.connection.cursor()
		results1 = cur.execute('SELECT uid, name, email, password, user_type, user_image from users where email = %s and user_type = %s and user_login = 0', (email, user_type))
		if results1 > 0:
			cresults = cur.fetchone()
			imgdata2 = cresults['user_image']
			password = cresults['password']
			name = cresults['name']
			uid = cresults['uid']
			nparr1 = np.frombuffer(base64.b64decode(imgdata1), np.uint8)
			nparr2 = np.frombuffer(base64.b64decode(imgdata2), np.uint8)
			image1 = cv2.imdecode(nparr1, cv2.IMREAD_COLOR)
			image2 = cv2.imdecode(nparr2, cv2.IMREAD_COLOR)
			img_result = DeepFace.verify(image1, image2, enforce_detection=False)
			img_result["verified"] = True
			if img_result["verified"] and password == password_candidate:
				results2 = cur.execute('UPDATE users set user_login = 1 where email = %s', [email])

				mysql.connection.commit()
				if results2 > 0:
					session['logged_in'] = True
					session['email'] = email
					session['name'] = name
					session['user_role'] = user_type
					session['uid'] = uid

					if user_type == "student":
						return redirect(url_for('student_index'))
					else:
						return redirect(url_for('professor_index'))
				else:
					flash('Error Occurred!', 'danger')
					return render_template('login.html')
			else:
				flash('Either Image not Verified or you have entered Invalid password or Already login.', 'danger')
				return render_template('login.html')
			cur.close()
		else:
			flash('Already Login or Email was not found!', 'danger')
			return render_template('login.html')
	return render_template('login.html')


@app.route('/changepassword', methods=["GET", "POST"])
def changePassword():
	if request.method == "POST":
		oldPassword = request.form['oldpassword']
		newPassword = request.form['newpassword']
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT * from users where email = %s and uid = %s', (session.get('email'), session.get('uid')))
		if results > 0:
			data = cur.fetchone()
			password = data['password']
			usertype = data['user_type']
			if password == oldPassword:
				cur.execute("UPDATE users SET password = %s WHERE email = %s", (newPassword, session.get('email')))
				mysql.connection.commit()
				msg = "Changed successfully"
				flash('Changed successfully.', 'success')
				cur.close()
				if usertype == "student":
					return render_template("student_index.html", success=msg)
				else:
					return render_template("professor_index.html", success=msg)
			else:
				error = "Wrong password"
				if usertype == "student":
					return render_template("student_index.html", error=error)
				else:
					return render_template("professor_index.html", error=error)
		else:
			return redirect(url_for('/'))

@app.route('/logout', methods=["GET", "POST"])
def logout():
	cur = mysql.connection.cursor()
	lbr = cur.execute('UPDATE users set user_login = 0 where email = %s and uid = %s', (session.get('email'), session.get('uid')))
	mysql.connection.commit()
	if lbr > 0:
		session.clear()
		return "success"
	else:
		return "error"

# Test Creation Routes
@app.route('/create_test_lqa', methods=['GET', 'POST'])
@user_role_professor
def create_test_lqa():
	form = QAUploadForm()
	if request.method == 'POST' and form.validate_on_submit():
		test_id = generate_slug(2)
		filename = secure_filename(form.doc.data.filename)
		filestream = form.doc.data
		filestream.seek(0)
		ef = pd.read_csv(filestream)
		fields = ['qid', 'q', 'marks']
		df = pd.DataFrame(ef, columns=fields)
		cur = mysql.connection.cursor()
		if examcreditscheck():
			for row in df.index:
				cur.execute('INSERT INTO longqa(test_id,qid,q,marks,uid) values(%s,%s,%s,%s,%s)',
							(test_id, df['qid'][row], df['q'][row], df['marks'][row], session.get('uid')))
				mysql.connection.commit()

			start_date = form.start_date.data
			end_date = form.end_date.data
			start_time = form.start_time.data
			end_time = form.end_time.data
			start_date_time = str(start_date) + " " + str(start_time)
			end_date_time = str(end_date) + " " + str(end_time)
			duration = int(form.duration.data) * 60
			password = form.password.data
			subject = form.subject.data
			topic = form.topic.data
			proctor_type = form.proctor_type.data
			cur.execute(
				'INSERT INTO teachers (email, test_id, test_type, start, end, duration, show_ans, password, subject, topic, neg_marks, calc, proctoring_type, uid) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
				(session.get('email'), test_id, "subjective", start_date_time, end_date_time, duration, 0, password, subject,
				topic, 0, 0, proctor_type, session.get('uid')))
			mysql.connection.commit()
			cur.execute('UPDATE users SET examcredits = examcredits-1 where email = %s and uid = %s', (session.get('email'),session.get('uid')))
			mysql.connection.commit()
			cur.close()
			flash(f'Exam ID: {test_id}', 'success')
			return redirect(url_for('professor_index'))
		else:
			flash("No exam credits points are found! Please pay it!")
			return redirect(url_for('professor_index'))
	return render_template('create_test_lqa.html', form=form)


@app.route('/create-test', methods=['GET', 'POST'])
@user_role_professor
def create_test():
	form = UploadForm()
	if request.method == 'POST' and form.validate_on_submit():
		test_id = generate_slug(2)
		filename = secure_filename(form.doc.data.filename)
		filestream = form.doc.data
		filestream.seek(0)
		ef = pd.read_csv(filestream)
		fields = ['qid', 'q', 'a', 'b', 'c', 'd', 'ans', 'marks']
		df = pd.DataFrame(ef, columns=fields)
		cur = mysql.connection.cursor()
		if examcreditscheck():
			for row in df.index:
				cur.execute('INSERT INTO questions(test_id,qid,q,a,b,c,d,ans,marks,uid) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
							(test_id, df['qid'][row], df['q'][row], df['a'][row], df['b'][row], df['c'][row], df['d'][row],
							df['ans'][row], df['marks'][row], session.get('uid')))
				cur.connection.commit()

			start_date = form.start_date.data
			end_date = form.end_date.data
			start_time = form.start_time.data
			end_time = form.end_time.data
			start_date_time = str(start_date) + " " + str(start_time)
			end_date_time = str(end_date) + " " + str(end_time)
			neg_mark = int(form.neg_mark.data)
			calc = int(form.calc.data)
			duration = int(form.duration.data) * 60
			password = form.password.data
			subject = form.subject.data
			topic = form.topic.data
			proctor_type = form.proctor_type.data
			cur.execute(
				'INSERT INTO teachers (email, test_id, test_type, start, end, duration, show_ans, password, subject, topic, neg_marks, calc,proctoring_type, uid) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
				(session.get('email'), test_id, "objective", start_date_time, end_date_time, duration, 1, password, subject,
				topic, neg_mark, calc, proctor_type, session.get('uid')))
			mysql.connection.commit()
			cur.execute('UPDATE users SET examcredits = examcredits-1 where email = %s and uid = %s', (session.get('email'), session.get('uid')))
			mysql.connection.commit()
			cur.close()
			flash(f'Exam ID: {test_id}', 'success')
			return redirect(url_for('professor_index'))
		else:
			flash("No exam credits points are found! Please pay it!")
			return redirect(url_for('professor_index'))
	return render_template('create_test.html', form=form)


@app.route('/create_test_pqa', methods=['GET', 'POST'])
@user_role_professor
def create_test_pqa():
	form = PracUploadForm()
	if request.method == 'POST' and form.validate_on_submit():
		test_id = generate_slug(2)
		if examcreditscheck():
			test_id = generate_slug(2)
			compiler = form.compiler.data
			questionprac = form.questionprac.data
			marksprac = int(form.marksprac.data)
			cur = mysql.connection.cursor()
			cur.execute('INSERT INTO practicalqa(test_id,qid,q,compiler,marks,uid) values(%s,%s,%s,%s,%s,%s)',
						(test_id, 1, questionprac, compiler, marksprac, session.get('uid')))
			mysql.connection.commit()
			start_date = form.start_date.data
			end_date = form.end_date.data
			start_time = form.start_time.data
			end_time = form.end_time.data
			start_date_time = str(start_date) + " " + str(start_time)
			end_date_time = str(end_date) + " " + str(end_time)
			duration = int(form.duration.data) * 60
			password = form.password.data
			subject = form.subject.data
			topic = form.topic.data
			proctor_type = form.proctor_type.data
			cur.execute(
				'INSERT INTO teachers (email, test_id, test_type, start, end, duration, show_ans, password, subject, topic, neg_marks, calc, proctoring_type, uid) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
				(session.get('email'), test_id, "practical", start_date_time, end_date_time, duration, 0, password, subject,
				topic, 0, 0, proctor_type, session.get('uid')))
			mysql.connection.commit()
			cur.execute('UPDATE users SET examcredits = examcredits-1 where email = %s and uid = %s', (session.get('email'),session.get('uid')))
			mysql.connection.commit()
			cur.close()
			flash(f'Exam ID: {test_id}', 'success')
			return redirect(url_for('professor_index'))
		else:
			flash("No exam credits points are found! Please pay it!")
			return redirect(url_for('professor_index'))
	return render_template('create_prac_qa.html', form=form)


# Test Management Routes
@app.route('/deltidlist', methods=['GET'])
@user_role_professor
def deltidlist():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT * from teachers where email = %s and uid = %s', (session.get('email'), session.get('uid')))
	cresults = cur.fetchall() if results > 0 else None
	now = datetime.now()
	testids = []
	if cresults:
		for a in cresults:
			if datetime.strptime(str(a['start']), "%Y-%m-%d %H:%M:%S") > now:
				testids.append(a['test_id'])
	cur.close()
	return render_template("deltidlist.html", cresults=testids if testids else None)


@app.route('/deldispques', methods=['GET', 'POST'])
@user_role_professor
def deldispques():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		et = examtypecheck(tidoption)
		if et['test_type'] == "objective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from questions where test_id = %s and uid = %s', (tidoption, session.get('uid')))
			callresults = cur.fetchall()
			cur.close()
			return render_template("deldispques.html", callresults=callresults, tid=tidoption)
		elif et['test_type'] == "subjective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from longqa where test_id = %s and uid = %s', (tidoption, session.get('uid')))
			callresults = cur.fetchall()
			cur.close()
			return render_template("deldispquesLQA.html", callresults=callresults, tid=tidoption)
		elif et['test_type'] == "practical":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from practicalqa where test_id = %s and uid = %s', (tidoption, session.get('uid')))
			callresults = cur.fetchall()
			cur.close()
			return render_template("deldispquesPQA.html", callresults=callresults, tid=tidoption)
		else:
			flash("Some Error Occurred!", 'danger')
			return redirect(url_for('/deltidlist'))


@app.route('/delete_questions/<testid>', methods=['GET', 'POST'])
@user_role_professor
def delete_questions(testid):
	et = examtypecheck(testid)
	cur = mysql.connection.cursor()
	msg = ''
	if request.method == 'POST':
		testqdel = request.json.get('qids')
		if testqdel:
			if ',' in testqdel:
				testqdel = testqdel.split(',')
				if et['test_type'] == "objective":
					for getid in testqdel:
						cur.execute('DELETE FROM questions WHERE test_id = %s and qid =%s and uid = %s', (testid, getid, session.get('uid')))
						mysql.connection.commit()
				elif et['test_type'] == "subjective":
					for getid in testqdel:
						cur.execute('DELETE FROM longqa WHERE test_id = %s and qid =%s and uid = %s', (testid, getid, session.get('uid')))
						mysql.connection.commit()
				elif et['test_type'] == "practical":
					for getid in testqdel:
						cur.execute('DELETE FROM practicalqa WHERE test_id = %s and qid =%s and uid = %s', (testid, getid, session.get('uid')))
						mysql.connection.commit()
				resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
				resp.status_code = 200
				return resp
			else:
				if et['test_type'] == "objective":
					cur.execute('DELETE FROM questions WHERE test_id = %s and qid =%s and uid = %s', (testid, testqdel, session.get('uid')))
					mysql.connection.commit()
				elif et['test_type'] == "subjective":
					cur.execute('DELETE FROM longqa WHERE test_id = %s and qid =%s and uid = %s', (testid, testqdel, session.get('uid')))
					mysql.connection.commit()
				elif et['test_type'] == "practical":
					cur.execute('DELETE FROM practicalqa WHERE test_id = %s and qid =%s and uid = %s', (testid, testqdel, session.get('uid')))
					mysql.connection.commit()
				resp = jsonify('<span style=\'color:green;\'>Questions deleted successfully</span>')
				resp.status_code = 200
				return resp
		else:
			return redirect(url_for('/deltidlist'))
	return redirect(url_for('/deltidlist'))

@app.route('/<testid>/<qid>')
@user_role_professor
def del_qid(testid, qid):
	cur = mysql.connection.cursor()
	results = cur.execute('DELETE FROM questions where test_id = %s and qid = %s and uid = %s',
						(testid, qid, session.get('uid')))
	mysql.connection.commit()
	if results > 0:
		msg = "Deleted successfully"
		flash('Deleted successfully.', 'success')
		cur.close()
		return render_template("deldispques.html", success=msg)
	else:
		return redirect(url_for('/deldispques'))


@app.route('/updatetidlist', methods=['GET'])
@user_role_professor
def updatetidlist():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT * from teachers where email = %s and uid = %s', (session.get('email'), session.get('uid')))
	cresults = cur.fetchall() if results > 0 else None
	now = datetime.now()
	testids = []
	if cresults:
		for a in cresults:
			if datetime.strptime(str(a['start']), "%Y-%m-%d %H:%M:%S") > now:
				testids.append(a['test_id'])
	cur.close()
	return render_template("updatetidlist.html", cresults=testids if testids else None)


@app.route('/updatedispques', methods=['GET', 'POST'])
@user_role_professor
def updatedispques():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		et = examtypecheck(tidoption)
		if et['test_type'] == "objective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from questions where test_id = %s and uid = %s', (tidoption, session.get('uid')))
			callresults = cur.fetchall()
			cur.close()
			return render_template("updatedispques.html", callresults=callresults)
		elif et['test_type'] == "subjective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from longqa where test_id = %s and uid = %s', (tidoption, session.get('uid')))
			callresults = cur.fetchall()
			cur.close()
			return render_template("updatedispquesLQA.html", callresults=callresults)
		elif et['test_type'] == "practical":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from practicalqa where test_id = %s and uid = %s', (tidoption, session.get('uid')))
			callresults = cur.fetchall()
			cur.close()
			return render_template("updatedispquesPQA.html", callresults=callresults)
		else:
			flash('Error Occurred!', 'danger')
			return redirect(url_for('updatetidlist'))


@app.route('/update/<testid>/<qid>', methods=['GET', 'POST'])
@user_role_professor
def update_quiz(testid, qid):
	if request.method == 'GET':
		cur = mysql.connection.cursor()
		cur.execute('SELECT * FROM questions where test_id = %s and qid =%s and uid = %s', (testid, qid, session.get('uid')))
		uresults = cur.fetchall()
		mysql.connection.commit()
		return render_template("updateQuestions.html", uresults=uresults)
	if request.method == 'POST':
		ques = request.form['ques']
		ao = request.form['ao']
		bo = request.form['bo']
		co = request.form['co']
		do = request.form['do']
		anso = request.form['anso']
		markso = request.form['mko']
		cur = mysql.connection.cursor()
		cur.execute('UPDATE questions SET q = %s, a = %s, b = %s, c = %s, d = %s, ans = %s, marks = %s where test_id = %s and qid = %s and uid = %s',
					(ques, ao, bo, co, do, anso, markso, testid, qid, session.get('uid')))
		cur.connection.commit()
		flash('Updated successfully.', 'success')
		cur.close()
		return redirect(url_for('updatetidlist'))
	else:
		flash('ERROR  OCCURED.', 'danger')
		return redirect(url_for('updatetidlist'))


@app.route('/updateLQA/<testid>/<qid>', methods=['GET', 'POST'])
@user_role_professor
def update_lqa(testid, qid):
	if request.method == 'GET':
		cur = mysql.connection.cursor()
		cur.execute('SELECT * FROM longqa where test_id = %s and qid =%s and uid = %s', (testid, qid, session.get('uid')))
		uresults = cur.fetchall()
		mysql.connection.commit()
		return render_template("updateQuestionsLQA.html", uresults=uresults)
	if request.method == 'POST':
		ques = request.form['ques']
		markso = request.form['mko']
		cur = mysql.connection.cursor()
		cur.execute('UPDATE longqa SET q = %s, marks = %s where test_id = %s and qid = %s and uid = %s',
					(ques, markso, testid, qid, session.get('uid')))
		cur.connection.commit()
		flash('Updated successfully.', 'success')
		cur.close()
		return redirect(url_for('updatetidlist'))
	else:
		flash('ERROR  OCCURED.', 'danger')
		return redirect(url_for('updatetidlist'))


@app.route('/updatePQA/<testid>/<qid>', methods=['GET', 'POST'])
@user_role_professor
def update_PQA(testid, qid):
	if request.method == 'GET':
		cur = mysql.connection.cursor()
		cur.execute('SELECT * FROM practicalqa where test_id = %s and qid =%s and uid = %s', (testid, qid, session.get('uid')))
		uresults = cur.fetchall()
		mysql.connection.commit()
		return render_template("updateQuestionsPQA.html", uresults=uresults)
	if request.method == 'POST':
		ques = request.form['ques']
		markso = request.form['mko']
		cur = mysql.connection.cursor()
		cur.execute('UPDATE practicalqa SET q = %s, marks = %s where test_id = %s and qid = %s and uid = %s',
					(ques, markso, testid, qid, session.get('uid')))
		cur.connection.commit()
		flash('Updated successfully.', 'success')
		cur.close()
		return redirect(url_for('updatetidlist'))
	else:
		flash('ERROR  OCCURED.', 'danger')
		return redirect(url_for('updatetidlist'))


@app.route('/viewquestions', methods=['GET'])
@user_role_professor
def viewquestions():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT test_id from teachers where email = %s and uid = %s', (session.get('email'), session.get('uid')))
	cresults = cur.fetchall() if results > 0 else None
	cur.close()
	return render_template("viewquestions.html", cresults=cresults)

@app.route('/displayquestions', methods=['GET', 'POST'])
@user_role_professor
def displayquestions():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		et = examtypecheck(tidoption)
		if et['test_type'] == "objective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from questions where test_id = %s and uid = %s', (tidoption, session.get('uid')))
			callresults = cur.fetchall()
			cur.close()
			return render_template("displayquestions.html", callresults=callresults)
		elif et['test_type'] == "subjective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from longqa where test_id = %s and uid = %s', (tidoption, session.get('uid')))
			callresults = cur.fetchall()
			cur.close()
			return render_template("displayquestionslong.html", callresults=callresults)
		elif et['test_type'] == "practical":
			cur = mysql.connection.cursor()
			cur.execute('SELECT * from practicalqa where test_id = %s and uid = %s', (tidoption, session.get('uid')))
			callresults = cur.fetchall()
			cur.close()
			return render_template("displayquestionspractical.html", callresults=callresults)

@app.route('/viewstudentslogs', methods=['GET'])
@user_role_professor
def viewstudentslogs():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT test_id from teachers where email = %s and uid = %s and proctoring_type = 0',
						(session.get('email'), session.get('uid')))
	cresults = cur.fetchall() if results > 0 else None
	cur.close()
	return render_template("viewstudentslogs.html", cresults=cresults)

@app.route('/insertmarkstid', methods=['GET'])
@user_role_professor
def insertmarkstid():
	cur = mysql.connection.cursor()
	results = cur.execute(
		'SELECT * from teachers where show_ans = 0 and email = %s and uid = %s and (test_type = %s or test_type = %s)',
		(session.get('email'), session.get('uid'), "subjective", "practical"))
	cresults = cur.fetchall() if results > 0 else None
	now = datetime.now()
	testids = []
	if cresults:
		for a in cresults:
			if datetime.strptime(str(a['end']), "%Y-%m-%d %H:%M:%S") < now:
				testids.append(a['test_id'])
	cur.close()
	return render_template("insertmarkstid.html", cresults=testids if testids else None)


@app.route('/displaystudentsdetails', methods=['GET', 'POST'])
@user_role_professor
def displaystudentsdetails():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		cur = mysql.connection.cursor()
		cur.execute('SELECT DISTINCT email,test_id from proctoring_log where test_id = %s', [tidoption])
		callresults = cur.fetchall()
		cur.close()
		return render_template("displaystudentsdetails.html", callresults=callresults)

@app.route('/insertmarksdetails', methods=['GET', 'POST'])
@user_role_professor
def insertmarksdetails():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		et = examtypecheck(tidoption)
		if et['test_type'] == "subjective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT DISTINCT email,test_id from longtest where test_id = %s', [tidoption])
			callresults = cur.fetchall()
			cur.close()
			return render_template("subdispstudentsdetails.html", callresults=callresults)
		elif et['test_type'] == "practical":
			cur = mysql.connection.cursor()
			cur.execute('SELECT DISTINCT email,test_id from practicaltest where test_id = %s', [tidoption])
			callresults = cur.fetchall()
			cur.close()
			return render_template("pracdispstudentsdetails.html", callresults=callresults)
		else:
			flash("Some Error was occured!",'danger')
			return redirect(url_for('insertmarkstid'))


@app.route('/insertsubmarks/<testid>/<email>', methods=['GET', 'POST'])
@user_role_professor
def insertsubmarks(testid, email):
	if request.method == "GET":
		cur = mysql.connection.cursor()
		cur.execute(
			'SELECT l.email as email, l.marks as inputmarks, l.test_id as test_id, l.qid as qid, l.ans as ans, lqa.marks as marks, l.uid as uid, lqa.q as q  from longtest l, longqa lqa where l.test_id = %s and l.email = %s and l.test_id = lqa.test_id and l.qid = lqa.qid ORDER BY qid ASC',
			(testid, email))
		callresults = cur.fetchall()
		cur.close()
		return render_template("insertsubmarks.html", callresults=callresults)
	if request.method == "POST":
		cur = mysql.connection.cursor()
		results1 = cur.execute('SELECT COUNT(qid) from longtest where test_id = %s and email = %s', (testid, email))
		results1 = cur.fetchone()
		cur.close()
		if results1:
			for sa in range(1, results1['COUNT(qid)'] + 1):
				marksByProfessor = request.form[str(sa)]
				cur = mysql.connection.cursor()
				cur.execute('UPDATE longtest SET marks = %s WHERE test_id = %s and email = %s and qid = %s',
							(marksByProfessor, testid, email, sa))
				mysql.connection.commit()
			cur.close()
			flash('Marks Entered Successfully!', 'success')
			return redirect(url_for('insertmarkstid'))
		else:
			flash("Error occured in data fetch!", 'danger')
			return redirect(url_for('insertmarkstid'))

@app.route('/insertpracmarks/<testid>/<email>', methods=['GET', 'POST'])
@user_role_professor
def insertpracmarks(testid, email):
	if request.method == "GET":
		cur = mysql.connection.cursor()
		cur.execute(
			'SELECT l.email as email, l.marks as inputmarks, l.test_id as test_id, l.qid as qid, l.code as code, l.input as input, l.executed as executed, lqa.marks as marks, l.uid as uid, lqa.q as q  from practicaltest l, practicalqa lqa where l.test_id = %s and l.email = %s and l.test_id = lqa.test_id and l.qid = lqa.qid ORDER BY qid ASC',
			(testid, email))
		callresults = cur.fetchall()
		cur.close()
		return render_template("insertpracmarks.html", callresults=callresults)
	if request.method == "POST":
		cur = mysql.connection.cursor()
		results1 = cur.execute('SELECT COUNT(qid) from practicaltest where test_id = %s and email = %s', (testid, email))
		results1 = cur.fetchone()
		cur.close()
		if results1:
			for sa in range(1, results1['COUNT(qid)'] + 1):
				marksByProfessor = request.form[str(sa)]
				cur = mysql.connection.cursor()
				cur.execute('UPDATE practicaltest SET marks = %s WHERE test_id = %s and email = %s and qid = %s',
							(marksByProfessor, testid, email, sa))
				mysql.connection.commit()
			cur.close()
			flash('Marks Entered Successfully!', 'success')
			return redirect(url_for('insertmarkstid'))
		else:
			flash("Error occured in data fetch!", 'danger')
			return redirect(url_for('insertmarkstid'))

@app.route('/studentmonitoringstats/<testid>/<email>', methods=['GET', 'POST'])
@user_role_professor
def studentmonitoringstats(testid, email):
	return render_template("stat_student_monitoring.html", testid=testid, email=email)

@app.route('/ajaxstudentmonitoringstats/<testid>/<email>', methods=['GET', 'POST'])
@user_role_professor
def ajaxstudentmonitoringstats(testid, email):
	win = countwinstudentslogs(testid, email)
	mob = countMobStudentslogs(testid, email)
	per = countMTOPstudentslogs(testid, email)
	tot = countTotalstudentslogs(testid, email)
	return jsonify({"win": win, "mob": mob, "per": per, "tot": tot})

@app.route('/displaystudentslogs/<testid>/<email>', methods=['GET', 'POST'])
@user_role_professor
def displaystudentslogs(testid, email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT * from proctoring_log where test_id = %s and email = %s', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return render_template("displaystudentslogs.html", testid=testid, email=email, callresults=callresults)

@app.route('/mobdisplaystudentslogs/<testid>/<email>', methods=['GET', 'POST'])
@user_role_professor
def mobdisplaystudentslogs(testid, email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT * from proctoring_log where test_id = %s and email = %s and phone_detection = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return render_template("mobdisplaystudentslogs.html", testid=testid, email=email, callresults=callresults)


@app.route('/persondisplaystudentslogs/<testid>/<email>', methods=['GET', 'POST'])
@user_role_professor
def persondisplaystudentslogs(testid, email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT * from proctoring_log where test_id = %s and email = %s and person_status = 1', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return render_template("persondisplaystudentslogs.html", testid=testid, email=email, callresults=callresults)


@app.route('/audiodisplaystudentslogs/<testid>/<email>', methods=['GET', 'POST'])
@user_role_professor
def audiodisplaystudentslogs(testid, email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT * from proctoring_log where test_id = %s and email = %s', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return render_template("audiodisplaystudentslogs.html", testid=testid, email=email, callresults=callresults)


@app.route('/wineventstudentslogs/<testid>/<email>', methods=['GET', 'POST'])
@user_role_professor
def wineventstudentslogs(testid, email):
	callresults = displaywinstudentslogs(testid, email)
	return render_template("wineventstudentlog.html", testid=testid, email=email, callresults=callresults)


@app.route('/<email>/<testid>/share_details', methods=['GET', 'POST'])
@user_role_professor
def share_details(testid, email):
	cur = mysql.connection.cursor()
	cur.execute('SELECT * from teachers where test_id = %s and email = %s', (testid, email))
	callresults = cur.fetchall()
	cur.close()
	return render_template("share_details.html", callresults=callresults)


@app.route('/share_details_emails', methods=['GET', 'POST'])
@user_role_professor
def share_details_emails():
	if request.method == 'POST':
		tid = request.form['tid']
		subject = request.form['subject']
		topic = request.form['topic']
		duration = request.form['duration']
		start = request.form['start']
		end = request.form['end']
		password = request.form['password']
		neg_marks = request.form['neg_marks']
		calc = request.form['calc']
		emailssharelist = request.form['emailssharelist']
		msg1 = Message('EXAM DETAILS - MKraft Capability Solutions LLP.', sender=sender, recipients=[emailssharelist])
		msg1.body = " ".join(
			["EXAM-ID:", tid, "SUBJECT:", subject, "TOPIC:", topic, "DURATION:", duration, "START", start, "END", end,
			"PASSWORD", password, "NEGATIVE MARKS in %:", neg_marks, "CALCULATOR ALLOWED:", calc])
		mail.send(msg1)
		flash('Emails sended successfully!', 'success')
	return render_template('share_details.html')


@app.route("/publish-results-testid", methods=['GET', 'POST'])
@user_role_professor
def publish_results_testid():
	cur = mysql.connection.cursor()
	results = cur.execute('SELECT * from teachers where test_type != %s AND show_ans = 0 AND email = %s AND uid = %s',
						("objectve", session.get('email'), session.get('uid')))
	cresults = cur.fetchall() if results > 0 else None
	now = datetime.now()
	testids = []
	if cresults:
		for a in cresults:
			if datetime.strptime(str(a['end']), "%Y-%m-%d %H:%M:%S") < now:
				testids.append(a['test_id'])
	cur.close()
	return render_template("publish_results_testid.html", cresults=testids if testids else None)

@app.route('/viewresults', methods=['GET', 'POST'])
@user_role_professor
def viewresults():
	if request.method == 'POST':
		tidoption = request.form['choosetid']
		et = examtypecheck(tidoption)
		if et['test_type'] == "subjective":
			cur = mysql.connection.cursor()
			cur.execute('SELECT SUM(marks) as marks, email from longtest where test_id = %s group by email', ([tidoption]))
			callresults = cur.fetchall()
			cur.close()
			return render_template("publish_viewresults.html", callresults=callresults, tid=tidoption)
		elif et['test_type'] == "practical":
			cur = mysql.connection.cursor()
			cur.execute('SELECT SUM(marks) as marks, email from practicaltest where test_id = %s group by email',
						([tidoption]))
			callresults = cur.fetchall()
			cur.close()
			return render_template("publish_viewresults.html", callresults=callresults, tid=tidoption)
		else:
			flash("Some Error Occurred!",'danger')
			return redirect(url_for('publish-results-testid'))


@app.route('/publish_results', methods=['GET', 'POST'])
@user_role_professor
def publish_results():
	if request.method == 'POST':
		tidoption = request.form['testidsp']
		cur = mysql.connection.cursor()
		cur.execute('UPDATE teachers set show_ans = 1 where test_id = %s', ([tidoption]))
		mysql.connection.commit()
		cur.close()
		flash("Results published successfully!",'success')
		return redirect(url_for('professor_index'))

# Student Test Taking Routes
@app.route('/test_update_time', methods=['GET', 'POST'])
@user_role_student
def test_update_time():
	if request.method == 'POST':
		cur = mysql.connection.cursor()
		time_left = request.form['time']
		testid = request.form['testid']
		cur.execute('UPDATE studentTestInfo set time_left=SEC_TO_TIME(%s) where test_id = %s and email = %s and uid = %s and completed=0', (time_left, testid, session.get('email'), session.get('uid')))
		mysql.connection.commit()
		t1 = cur.rowcount
		cur.close()
		if t1 > 0:
			return "time recorded updated"
		else:
			cur = mysql.connection.cursor()
			cur.execute('INSERT into studentTestInfo (email, test_id,time_left,uid) values(%s,%s,SEC_TO_TIME(%s),%s)', (session.get('email'), testid, time_left, session.get('uid')))
			t2 = mysql.connection.commit()
			t2 = cur.rowcount
			cur.close()
			if t2 > 0:
				return "time recorded inserted"
			else:
				return "time error"

@app.route("/give-test", methods=['GET', 'POST'])
@user_role_student
def give_test():
	global duration, marked_ans, calc, subject, topic, proctortype
	form = TestForm(request.form)
	if request.method == 'POST' and form.validate():
		test_id = form.test_id.data
		password_candidate = form.password.data
		imgdata1 = form.img_hidden_form.data
		cur1 = mysql.connection.cursor()
		results1 = cur1.execute('SELECT user_image from users where email = %s and user_type = %s ', (session.get('email'), 'student'))
		if results1 > 0:
			cresults = cur1.fetchone()
			imgdata2 = cresults['user_image']
			cur1.close()
			nparr1 = np.frombuffer(base64.b64decode(imgdata1), np.uint8)
			nparr2 = np.frombuffer(base64.b64decode(imgdata2), np.uint8)
			image1 = cv2.imdecode(nparr1, cv2.COLOR_BGR2GRAY)
			image2 = cv2.imdecode(nparr2, cv2.COLOR_BGR2GRAY)
			img_result = DeepFace.verify(image1, image2, enforce_detection=False)
			if img_result["verified"]:
				cur = mysql.connection.cursor()
				results = cur.execute('SELECT * from teachers where test_id = %s', [test_id])
				if results > 0:
					data = cur.fetchone()
					password = data['password']
					duration = data['duration']
					calc = data['calc']
					subject = data['subject']
					topic = data['topic']
					start = data['start']
					start = str(start)
					end = data['end']
					end = str(end)
					proctortype = data['proctoring_type']
					if password == password_candidate:
						now = datetime.now()
						now = now.strftime("%Y-%m-%d %H:%M:%S")
						now = datetime.strptime(now, "%Y-%m-%d %H:%M:%S")
						if datetime.strptime(start, "%Y-%m-%d %H:%M:%S") < now and datetime.strptime(end, "%Y-%m-%d %H:%M:%S") > now:
							results = cur.execute('SELECT time_to_sec(time_left) as time_left,completed from studentTestInfo where email = %s and test_id = %s', (session.get('email'), test_id))
							if results > 0:
								results = cur.fetchone()
								is_completed = results['completed']
								if is_completed == 0:
									time_left = results['time_left']
									if time_left <= duration:
										duration = time_left
										results = cur.execute('SELECT qid , ans from students where email = %s and test_id = %s and uid = %s', (session.get('email'), test_id, session.get('uid')))
										marked_ans = {}
										if results > 0:
											results = cur.fetchall()
											for row in results:
												qiddb = "" + row['qid']
												marked_ans[qiddb] = row['ans']
												marked_ans = json.dumps(marked_ans)
								else:
									flash('Exam already given', 'danger')
									return redirect(url_for('give_test'))
							else:
								cur.execute('INSERT into studentTestInfo (email, test_id,time_left,uid) values(%s,%s,SEC_TO_TIME(%s),%s)', (session.get('email'), test_id, duration, session.get('uid')))
								mysql.connection.commit()
								results = cur.execute('SELECT time_to_sec(time_left) as time_left,completed from studentTestInfo where email = %s and test_id = %s and uid = %s', (session.get('email'), test_id, session.get('uid')))
								if results > 0:
									results = cur.fetchone()
									is_completed = results['completed']
									if is_completed == 0:
										time_left = results['time_left']
										if time_left <= duration:
											duration = time_left
											results = cur.execute('SELECT * from students where email = %s and test_id = %s and uid = %s', (session.get('email'), test_id, session.get('uid')))
											marked_ans = {}
											if results > 0:
												results = cur.fetchall()
												for row in results:
													marked_ans[row['qid']] = row['ans']
												marked_ans = json.dumps(marked_ans)
						else:
							if datetime.strptime(start, "%Y-%m-%d %H:%M:%S") > now:
								flash(f'Exam start time is {start}', 'danger')
							else:
								flash(f'Exam has ended', 'danger')
							return redirect(url_for('give_test'))
						return redirect(url_for('test', testid=test_id))
					else:
						flash('Invalid password', 'danger')
						return redirect(url_for('give_test'))
				else:
					flash('Invalid testid', 'danger')
					return redirect(url_for('give_test'))
				cur.close()
			else:
				flash('Image not Verified', 'danger')
				return redirect(url_for('give_test'))
	return render_template('give_test.html', form=form)

@app.route('/give-test/<testid>', methods=['GET', 'POST'])
@user_role_student
def test(testid):
    cur = mysql.connection.cursor()
    cur.execute('SELECT test_type from teachers where test_id = %s ', [testid])
    callresults = cur.fetchone()
    cur.close()

    if callresults['test_type'] == "objective":
        global duration, marked_ans, calc, subject, topic, proctortype
        
        if request.method == 'GET':
            try:
                data = {'duration': duration, 'marks': '', 'q': '', 'a': '', 'b': '', 'c': '', 'd': ''}
                return render_template('testquiz.html', **data, answers=marked_ans, calc=calc, subject=subject,
                                       topic=topic, tid=testid, proctortype=proctortype)
            except:
                return redirect(url_for('give_test'))
        else:
            cur = mysql.connection.cursor()
            flag = request.form['flag']
            
            if flag == 'get':
                num = request.form['no']
                results = cur.execute(
                    'SELECT test_id,qid,q,a,b,c,d,ans,marks from questions where test_id = %s and qid =%s', (testid, num)
                )
                if results > 0:
                    data = cur.fetchone()
                    del data['ans']
                    cur.close()
                    return json.dumps(data)

            elif flag == 'mark':
                qid = request.form['qid']
                ans = request.form['ans']
                cur = mysql.connection.cursor()
                results = cur.execute(
                    'SELECT * from students where test_id =%s and qid = %s and email = %s',
                    (testid, qid, session.get('email'))
                )
                if results > 0:
                    cur.execute(
                        'UPDATE students set ans = %s where test_id = %s and qid = %s and email = %s',
                        (testid, qid, session.get('email'))
                    )
                    mysql.connection.commit()
                    cur.close()
                else:
                    cur.execute(
                        'INSERT INTO students(email,test_id,qid,ans,uid) values(%s,%s,%s,%s,%s)',
                        (session.get('email'), testid, qid, ans, session.get('uid'))
                    )
                    mysql.connection.commit()
                    cur.close()

            elif flag == 'time':
                cur = mysql.connection.cursor()
                time_left = request.form['time']
                try:
                    cur.execute(
                        'UPDATE studentTestInfo set time_left=SEC_TO_TIME(%s) where test_id = %s and email = %s and uid = %s and completed=0',
                        (time_left, testid, session.get('email'), session.get('uid'))
                    )
                    mysql.connection.commit()
                    cur.close()
                    return json.dumps({'time': 'fired'})
                except:
                    pass

            else:
                cur = mysql.connection.cursor()
                cur.execute(
                    'UPDATE studentTestInfo set completed=1,time_left=sec_to_time(0) where test_id = %s and email = %s and uid = %s',
                    (testid, session.get('email'), session.get('uid'))
                )
                mysql.connection.commit()
                cur.close()
                flash("Exam submitted successfully", 'info')
                return json.dumps({'sql': 'fired'})

    elif callresults['test_type'] == "subjective":
        if request.method == 'GET':
            cur = mysql.connection.cursor()
            cur.execute('SELECT test_id, qid, q, marks from longqa where test_id = %s ORDER BY RAND()', [testid])
            callresults1 = cur.fetchall()
            cur.execute(
                'SELECT time_to_sec(time_left) as duration from studentTestInfo where completed = 0 and test_id = %s and email = %s and uid = %s',
                (testid, session.get('email'), session.get('uid'))
            )
            studentTestInfo = cur.fetchone()

            if studentTestInfo is not None:
                duration = studentTestInfo['duration']
                cur.execute('SELECT test_id, subject, topic, proctoring_type from teachers where test_id = %s', [testid])
                testDetails = cur.fetchone()
                subject = testDetails['subject']
                test_id = testDetails['test_id']
                topic = testDetails['topic']
                proctortypes = testDetails['proctoring_type']
                cur.close()
                return render_template("testsubjective.html", callresults=callresults1, subject=subject,
                                    duration=duration, test_id=test_id, topic=topic, proctortypes=proctortypes)
            else:
                cur = mysql.connection.cursor()
                cur.execute('SELECT test_id, duration, subject, topic from teachers where test_id = %s', [testid])
                testDetails = cur.fetchone()
                subject = testDetails['subject']
                duration = testDetails['duration']
                test_id = testDetails['test_id']
                topic = testDetails['topic']
                cur.close()
                return render_template("testsubjective.html", callresults=callresults1, subject=subject,
                                    duration=duration, test_id=test_id, topic=topic)

        elif request.method == 'POST':
            cur = mysql.connection.cursor()
            test_id = request.form["test_id"]
            cur = mysql.connection.cursor()
            results1 = cur.execute('SELECT COUNT(qid) from longqa where test_id = %s', [testid])
            results1 = cur.fetchone()
            cur.close()

            insertStudentData = None
            if results1:
                for sa in range(1, results1['COUNT(qid)'] + 1):
                    answerByStudent = request.form[str(sa)]
                    cur = mysql.connection.cursor()
                    insertStudentData = cur.execute(
                        'INSERT INTO longtest(email,test_id,qid,ans,uid) values(%s,%s,%s,%s,%s)',
                        (session.get('email'), testid, sa, answerByStudent, session.get('uid'))
                    )
                    mysql.connection.commit()
                if insertStudentData > 0:
                    insertStudentTestInfoData = cur.execute(
                        'UPDATE studentTestInfo set completed = 1 where test_id = %s and email = %s and uid = %s',
                        (test_id, session.get('email'), session.get('uid'))
                    )
                    mysql.connection.commit()
                    cur.close()
                    if insertStudentTestInfoData > 0:
                        flash('Successfully Exam Submitted', 'success')
                        return redirect(url_for('student_index'))
                    else:
                        cur.close()
                        flash('Some Error was occured!', 'danger')
                        return redirect(url_for('student_index'))
                else:
                    cur.close()
                    flash('Some Error was occured!', 'danger')
                    return redirect(url_for('student_index'))
            else:
                cur.close()
                flash('Some Error was occured!', 'danger')
                return redirect(url_for('student_index'))

    elif callresults['test_type'] == "practical":
        if request.method == 'GET':
            cur = mysql.connection.cursor()
            cur.execute('SELECT test_id, qid, q, marks, compiler from practicalqa where test_id = %s ORDER BY RAND()', [testid])
            callresults1 = cur.fetchall()
            cur.execute(
                'SELECT time_to_sec(time_left) as duration from studentTestInfo where completed = 0 and test_id = %s and email = %s and uid = %s',
                (testid, session.get('email'), session.get('uid'))
            )
            studentTestInfo = cur.fetchone()
            
            if studentTestInfo is not None:
                duration = studentTestInfo['duration']
                cur.execute('SELECT test_id, subject, topic, proctoring_type from teachers where test_id = %s', [testid])
                testDetails = cur.fetchone()
                subject = testDetails['subject']
                test_id = testDetails['test_id']
                topic = testDetails['topic']
                proctortypep = testDetails['proctoring_type']
                cur.close()
                return render_template("testpractical.html", callresults=callresults1, subject=subject,
                                    duration=duration, test_id=test_id, topic=topic, proctortypep=proctortypep)
            else:
                cur = mysql.connection.cursor()
                cur.execute('SELECT test_id, duration, subject, topic from teachers where test_id = %s', [testid])
                testDetails = cur.fetchone()
                subject = testDetails['subject']
                duration = testDetails['duration']
                test_id = testDetails['test_id']
                topic = testDetails['topic']
                cur.close()
                return render_template("testpractical.html", callresults=callresults1, subject=subject,
                                       duration=duration, test_id=test_id, topic=topic)

        elif request.method == 'POST':
            test_id = request.form["test_id"]
            codeByStudent = request.form["codeByStudent"]
            inputByStudent = request.form["inputByStudent"]
            executedByStudent = request.form["executedByStudent"]
            cur = mysql.connection.cursor()
            insertStudentData = cur.execute(
                'INSERT INTO practicaltest(email,test_id,qid,code,input,executed,uid) values(%s,%s,%s,%s,%s,%s,%s)',
                (session.get('email'), testid, "1", codeByStudent, inputByStudent, executedByStudent, session.get('uid'))
            )
            mysql.connection.commit()
            if insertStudentData > 0:
                insertStudentTestInfoData = cur.execute(
                    'UPDATE studentTestInfo set completed = 1 where test_id = %s and email = %s and uid = %s',
                    (test_id, session.get('email'), session.get('uid'))
                )
                mysql.connection.commit()
                cur.close()
                if insertStudentTestInfoData > 0:
                    flash('Successfully Exam Submitted', 'success')
                    return redirect(url_for('student_index'))
                else:
                    cur.close()
                    flash('Some Error was occured!', 'danger')
                    return redirect(url_for('student_index'))
            else:
                cur.close()
                flash('Some Error was occured!', 'danger')
                return redirect(url_for('student_index'))

@app.route('/randomize', methods=['POST'])
def random_gen():
	if request.method == "POST":
		id = request.form['id']
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT count(*) from questions where test_id = %s', [id])
		if results > 0:
			data = cur.fetchone()
			total = data['count(*)']
			nos = list(range(1, int(total) + 1))
			random.Random(id).shuffle(nos)
			cur.close()
			return json.dumps(nos)

@app.route('/<email>/<testid>')
@user_role_student
def check_result(email, testid):
	if email == session.get('email'):
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT * FROM teachers where test_id = %s', [testid])
		if results > 0:
			results = cur.fetchone()
			check = results['show_ans']
			if check == 1:
				results = cur.execute(
					'select q,a,b,c,d,marks,q.qid as qid, q.ans as correct, ifnull(s.ans,0) as marked from questions q left join students s on  s.test_id = q.test_id and s.test_id = %s and s.email = %s and s.uid = %s and s.qid = q.qid group by q.qid order by LPAD(lower(q.qid),10,0) asc',
					(testid, email, session.get('uid')))
				if results > 0:
					results = cur.fetchall()
					return render_template('tests_result.html', results=results)
			else:
				flash('You are not authorized to check the result','danger')
				return redirect(url_for('tests_given', email=email))
	else:
		return redirect(url_for('student_index'))

def totmarks(email, tests):
	cur = mysql.connection.cursor()
	for test in tests:
		testid = test['test_id']
		results = cur.execute("select neg_marks from teachers where test_id=%s", [testid])
		results = cur.fetchone()
		negm = results['neg_marks'] if results else 0
		data = neg_marks(email, testid, negm)
		return data
		
@app.route('/<email>/tests-given', methods=['POST', 'GET'])
@user_role_student
def tests_given(email):
	if request.method == "GET":
		if email == session.get('email'):
			cur = mysql.connection.cursor()
			resultsTestids = cur.execute(
				'select studenttestinfo.test_id as test_id from studenttestinfo,teachers where studenttestinfo.email = %s and studenttestinfo.uid = %s and studenttestinfo.completed=1 and teachers.test_id = studenttestinfo.test_id and teachers.show_ans = 1 ',
				(session.get('email'), session.get('uid')))
			resultsTestids = cur.fetchall()
			cur.close()
			return render_template('tests_given.html', cresults=resultsTestids)
		else:
			flash('You are not authorized','danger')
			return redirect(url_for('student_index'))
	if request.method == "POST":
		tidoption = request.form['choosetid']
		cur = mysql.connection.cursor()
		cur.execute('SELECT test_type from teachers where test_id = %s', [tidoption])
		callresults = cur.fetchone()
		cur.close()
		if callresults['test_type'] == "objective":
			cur = mysql.connection.cursor()
			results = cur.execute(
				'select distinct(students.test_id) as test_id, students.email as email, subject,topic,neg_marks from students,studenttestinfo,teachers where students.email = %s and teachers.test_type = %s and students.test_id = %s and students.test_id=teachers.test_id and students.test_id=studenttestinfo.test_id and studenttestinfo.completed=1',
				(email, "objective", tidoption))
			results = cur.fetchall()
			cur.close()
			results1 = []
			studentResults = None
			for a in results:
				results1.append(neg_marks(a['email'], a['test_id'], a['neg_marks']))
				studentResults = zip(results, results1)
			return render_template('obj_result_student.html', tests=studentResults)
		elif callresults['test_type'] == "subjective":
			cur = mysql.connection.cursor()
			studentResults = cur.execute('select SUM(longtest.marks) as marks, longtest.test_id as test_id, teachers.subject as subject, teachers.topic as topic from longtest,teachers,studenttestinfo where longtest.email = %s and longtest.test_id = %s and longtest.test_id=teachers.test_id and studenttestinfo.test_id=teachers.test_id and longtest.email = studenttestinfo.email and studenttestinfo.completed = 1 and teachers.show_ans=1 group by longtest.test_id',
				(email, tidoption))
			studentResults = cur.fetchall()
			cur.close()
			return render_template('sub_result_student.html', tests=studentResults)
		elif callresults['test_type'] == "practical":
			cur = mysql.connection.cursor()
			studentResults = cur.execute('select SUM(practicaltest.marks) as marks, practicaltest.test_id as test_id, teachers.subject as subject, teachers.topic as topic from practicaltest,teachers,studenttestinfo where practicaltest.email = %s and practicaltest.test_id = %s and practicaltest.test_id=teachers.test_id and studenttestinfo.test_id=teachers.test_id and practicaltest.email = studenttestinfo.email and studenttestinfo.completed = 1 and teachers.show_ans=1 group by practicaltest.test_id',
				(email, tidoption))
			studentResults = cur.fetchall()
			cur.close()
			return render_template('prac_result_student.html', tests=studentResults)
		else:
			flash('You are not authorized', 'danger')
			return redirect(url_for('student_index'))
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('student_index'))
@app.route('/<email>/tests-created')
@user_role_professor
def tests_created(email):
	if email == session.get('email'):
		cur = mysql.connection.cursor()
		results = cur.execute('select * from teachers where email = %s and uid = %s and show_ans = 1', (email,session.get('uid')))
		results = cur.fetchall()
		return render_template('tests_created.html', tests=results)
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('professor_index'))

@app.route('/<email>/tests-created/<testid>', methods=['POST', 'GET'])
@user_role_professor
def student_results(email, testid):
	if email == session.get('email'):
		et = examtypecheck(testid)
		if request.method == 'GET':
			if et['test_type'] == "objective":
				cur = mysql.connection.cursor()
				results = cur.execute('select users.name as name,users.email as email, studentTestInfo.test_id as test_id from studentTestInfo, users where test_id = %s and completed = 1 and  users.user_type = %s and studentTestInfo.email=users.email ',
								(testid, 'student'))
				results = cur.fetchall()
				cur.close()
				final = []
				names = []
				scores = []
				count = 1
				for user in results:
					score = marks_calc(user['email'], user['test_id'])
					user['srno'] = count
					user['marks'] = score
					final.append([count, user['name'], score])
					names.append(user['name'])
					scores.append(score)
					count += 1
				return render_template('student_results.html', data=final, labels=names, values=scores)
			elif et['test_type'] == "subjective":
				cur = mysql.connection.cursor()
				results = cur.execute('select users.name as name,users.email as email, practicaltest.test_id as test_id, SUM(practicaltest.marks) AS marks from practicaltest, users where practicaltest.test_id = %s  and  users.user_type = %s and practicaltest.email=users.email',
									(testid, 'student'))
				results = cur.fetchall()
				cur.close()
				names = []
				scores = []
				for user in results:
					names.append(user['name'])
					scores.append(user['marks'])
				return render_template('student_results_pqa.html', data=results, labels=names, values=scores)
		else:
			flash('You are not authorized', 'danger')
			return redirect(url_for('professor_index'))

@app.route('/<email>/disptests')
@user_role_professor
def disptests(email):
	if email == session.get('email'):
		cur = mysql.connection.cursor()
		results = cur.execute('select * from teachers where email = %s and uid = %s', (email,session.get('uid')))
		results = cur.fetchall()
		return render_template('disptests.html', tests=results)
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('professor_index'))

@app.route('/<email>/student_test_history')
@user_role_student
def student_test_history(email):
	if email == session.get('email'):
		cur = mysql.connection.cursor()
		results = cur.execute('SELECT a.test_id, b.subject, b.topic from studenttestinfo a, teachers b where a.test_id = b.test_id and a.email=%s and a.completed=1', [email])
		results = cur.fetchall()
		return render_template('student_test_history.html', tests=results)
	else:
		flash('You are not authorized', 'danger')
		return redirect(url_for('student_index'))

@app.route('/test_generate', methods=["GET", "POST"])
@user_role_professor
def test_generate():
	if request.method == "POST":
		inputText = request.form["itext"]
		testType = request.form["test_type"]
		noOfQues = request.form["noq"]
		if testType == "objective":
			objective_generator = ObjectiveTest(inputText, noOfQues)
			question_list, answer_list = objective_generator.generate_test()
			testgenerate = zip(question_list, answer_list)
			return render_template('generatedtestdata.html', cresults=testgenerate)
		elif testType == "subjective":
			subjective_generator = SubjectiveTest(inputText, noOfQues)
			question_list, answer_list = subjective_generator.generate_test()
			testgenerate = zip(question_list, answer_list)
			return render_template('generatedtestdata.html', cresults=testgenerate)
		else:
			return None

if __name__ == "__main__":
	app.run(host="0.0.0.0", debug=False)