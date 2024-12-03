from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory,jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
import os
from datetime import datetime
import pyotp
import smtplib
from email.mime.text import MIMEText
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Your_key'
app.config['MONGO_URI'] = 'Monogo_Atlas_connect_URl'
socketio = SocketIO(app)
bcrypt = Bcrypt(app)
mongo = PyMongo(app)

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html', username=session['username'])

logging.basicConfig(level=logging.DEBUG)

def send_otp_email(email, otp):
    sender_email = os.environ.get('EMAIL_USER')
    sender_password = os.environ.get('EMAIL_PASS')

    logging.debug(f"Sender email: {sender_email}")
    logging.debug(f"Password length: {len(sender_password) if sender_password else 0}")

    subject = "Your OTP for Chat App Registration"
    body = f"Your OTP is: {otp}"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = email

    try:
        logging.debug("Attempting to connect to SMTP server...")
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            logging.debug("Connected to SMTP server")
            logging.debug("Attempting to login...")
            smtp_server.login(sender_email, sender_password)
            logging.debug("Login successful")
            logging.debug("Sending email...")
            smtp_server.sendmail(sender_email, email, msg.as_string())
            logging.debug("Email sent successfully")
    except Exception as e:
        logging.error(f"Error sending OTP: {str(e)}")
        raise

    logging.debug("OTP email function completed")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if mongo.db.users.find_one({'username': username}):
            return 'Username already exists'

        if mongo.db.users.find_one({'email': email}):
            return 'Email already exists'

        # Generate OTP
        otp_secret = pyotp.random_base32()
        otp = pyotp.TOTP(otp_secret, interval=300)  # OTP valid for 5 minutes
        otp_value = otp.now()

        # Store user data and OTP secret temporarily
        session['temp_user'] = {
            'name': name,
            'username': username,
            'password': password,
            'email': email,
            'otp_secret': otp_secret
        }

        # Send OTP via email
        send_otp_email(email, otp_value)

        return redirect(url_for('verify_otp'))

    return render_template('register.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'temp_user' not in session:
        return redirect(url_for('register'))

    if request.method == 'POST':
        user_otp = request.form['otp']
        temp_user = session['temp_user']
        otp = pyotp.TOTP(temp_user['otp_secret'], interval=300)

        if otp.verify(user_otp):
            # OTP is valid, create the user
            hashed_password = bcrypt.generate_password_hash(temp_user['password']).decode('utf-8')
            mongo.db.users.insert_one({
                'name': temp_user['name'],
                'username': temp_user['username'],
                'password': hashed_password,
                'email': temp_user['email']
            })
            session.pop('temp_user', None)
            return redirect(url_for('login'))
        else:
            return 'Invalid OTP, please try again'

    return render_template('verify_otp.html')   

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = mongo.db.users.find_one({'username': username})

        if user and bcrypt.check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('chat'))
        return 'Invalid username or password'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

connected_users = {}

@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        username = session['username']
        sid = request.sid
        connected_users[username] = sid
        emit('user_connected', {'username': username}, broadcast=True)
        emit('update_user_list', {'users': list(connected_users.keys())}, broadcast=True)
        print(f"{username} connected with SID {sid}")

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username in connected_users:
        del connected_users[username]
        emit('user_disconnected', {'username': username}, broadcast=True)
        emit('update_user_list', {'users': list(connected_users.keys())}, broadcast=True)
        print(f"{username} disconnected")

@socketio.on('send_message')
def handle_send_message(data):
    sender = session.get('username')
    message = data['message']
    recipient = data['recipient']
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if sender and recipient:
        message_data = {
            'sender': sender,
            'message': message,
            'timestamp': timestamp
        }
        
        recipient_sid = connected_users.get(recipient)
        if recipient_sid:
            emit('new_message', message_data, room=recipient_sid)
        emit('new_message', message_data, room=request.sid)

@socketio.on('upload_file')
def handle_file_upload(data):
    file = data['file']
    filename = file['name']
    content = file['content']
    
    with open(os.path.join(UPLOAD_FOLDER, filename), 'wb') as f:
        f.write(content)
    
    sender = session.get('username')
    recipient = data['recipient']
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if sender and recipient:
        file_data = {
            'sender': sender,
            'filename': filename,
            'timestamp': timestamp
        }
        
        recipient_sid = connected_users.get(recipient)
        if recipient_sid:
            emit('new_file', file_data, room=recipient_sid)
        emit('new_file', file_data, room=request.sid)

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = mongo.db.users.find_one({'email': email})
        if user:
            otp_secret = pyotp.random_base32()
            otp = pyotp.TOTP(otp_secret, interval=300)
            otp_value = otp.now()
            
            mongo.db.users.update_one({'email': email}, {'$set': {'reset_otp_secret': otp_secret}})
            
            send_otp_email(email, otp_value)
            
            return jsonify({'success': True, 'message': 'OTP sent to your email'})
        else:
            return jsonify({'success': False, 'message': 'Email not found'})
    return render_template('forget.html')


@app.route('/verify-forgot-password-otp', methods=['POST'])
def verify_forgot_password_otp():
    email = request.form['email']
    user_otp = request.form['otp']
    new_password = request.form['new_password']
    
    user = mongo.db.users.find_one({'email': email})
    if user and 'reset_otp_secret' in user:
        otp = pyotp.TOTP(user['reset_otp_secret'], interval=300)
        if otp.verify(user_otp):
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            mongo.db.users.update_one({'email': email}, {
                '$set': {'password': hashed_password},
                '$unset': {'reset_otp_secret': ''}
            })
            return jsonify({'success': True, 'message': 'Password reset successfully'})
        else:
            return jsonify({'success': False, 'message': 'Invalid OTP'})
    else:
        return jsonify({'success': False, 'message': 'Invalid request'})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)