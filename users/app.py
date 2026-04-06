import sqlite3
import os
from flask import Flask, request, jsonify
import json
import hmac
import base64
import hashlib
import requests


app = Flask(__name__)
db_name = "user.db"
sql_file = "user.sql"
db_flag = False

reservations_url = "http://reservations:5000"
payments_url = "http://payments:5000"


'''
@app.route('/', methods=(['GET']))
def index():
	MICRO2URL = "http://localhost:5001/test_micro"
	r = requests.get(url = MICRO2URL)
	data = r.json()

	return data


@app.route('/test_micro', methods=(['GET']))
def test_micro():

	return "This is Microservice 1" 
'''


def create_db():
    conn = sqlite3.connect(db_name)
    
    with open(sql_file, 'r') as sql_startup:
    	init_db = sql_startup.read()
    cursor = conn.cursor()
    cursor.executescript(init_db)
    conn.commit()
    conn.close()
    global db_flag
    db_flag = True
    return conn

def get_db():
	if not db_flag:
		create_db()
	conn = sqlite3.connect(db_name)
	conn.execute('PRAGMA foreign_keys = ON')
	return conn

@app.route('/', methods=(['GET']))
def index():
	conn = get_db()
	cursor = conn.cursor()
	cursor.execute("SELECT * FROM test;")
	result = cursor.fetchall()
	conn.close()

	return result


def reading_key():
	try:
		with open("key.txt",'r') as fp:
			key = fp.read().strip()
		return key
	except FileNotFoundError:
		raise Exception("key.txt file not found")



def check_pswd(first_name, last_name, username, password):
	if len(password)<8:
		return False
	
	if ' ' in password:
		return False
	
	if not any(char.isupper() for char in password):
		return False
	
	chars = " ^_.*@#$&|!-+><=()[]{}\"\\"
	if any(ch in password for ch in chars):
		return False

	pswdLowered = password.lower()
	usernameLowered = username.lower()
	first_nameLowered = first_name.lower()
	last_nameLowered = last_name.lower()
	elem = [usernameLowered, first_nameLowered, last_nameLowered]
	
	for i in elem:
		if pswdLowered in i:
			return False
	
	return True



def hashing(password, salt):
	pass_with_salt = password + salt
	hashed_pass = hashlib.sha256(pass_with_salt.encode('utf-8')).hexdigest()
	return hashed_pass



def url_encoding(data):
    return base64.urlsafe_b64encode(json.dumps(data, separators=(', ', ': ')).encode('utf-8')).decode('utf-8')




def jwt_token(username):
	key = reading_key()

	header_part = url_encoding({"alg": "HS256", "typ": "JWT"})
	payload_part = url_encoding({"username": username})
	output = f"{header_part}.{payload_part}".encode()
	signature = hmac.new(key.encode('utf-8'), output, hashlib.sha256).hexdigest() 

	token = f"{header_part}.{payload_part}.{signature}"
	return token



def jwt_verification(token):
	try:
		parts = token.split('.')
		if len(parts) != 3:
			return None
			
		key = reading_key()
		
		header_part,payload_part,sign_part = parts
		output = f"{header_part}.{payload_part}".encode()
		
		sign_part2 = hmac.new(key.encode('utf-8'), output, hashlib.sha256).hexdigest()
		
		if sign_part != sign_part2:
			return None
		
		decoded_bytes = base64.urlsafe_b64decode(payload_part)
		decoded_payload = json.loads(decoded_bytes.decode('utf-8'))
		
		#if decoded_payload.get('access') != "True":
			#return None
		
		return decoded_payload.get('username')
	
	except Exception as e:
		return None



@app.route('/create_user', methods=(['POST']))
def create_user():
	
	conn = get_db()
	curr = conn.cursor()
	
	output = request.form
	first_name = output.get('first_name').strip()
	last_name = output.get('last_name').strip()
	username = output.get('username').strip()
	email = output.get('email_address').strip()
	driver = output.get('driver')
	deposit = output.get('deposit').strip()
	password = output.get('password')
	salt = output.get('salt')


	if not all([first_name, last_name, username, email, driver, deposit, password, salt]):
		return jsonify({"status": 4, "pass_hash": "NULL"})

	verify_pswd = check_pswd(first_name, last_name, username, password)
	if verify_pswd == False:
		return jsonify({"status": 4, "pass_hash": "NULL"})

	hashed_pswd = hashing(password, salt)

	try:
		curr.execute("SELECT username FROM users WHERE username =?", (username,))
		if curr.fetchone():
			curr.close()
			return jsonify({"status": 2, "pass_hash": "NULL"})

		curr.execute("SELECT email_address FROM users WHERE email_address = ?", (email,))
		if curr.fetchone():
			curr.close()
			return jsonify({"status": 3, "pass_hash": "NULL"})
		
		if driver in ('True', 'true', True):
			driver = 1
	
		else:
			driver = 0
		
		curr.execute("INSERT INTO users (first_name, last_name, username, email_address, driver, password, salt) VALUES (?,?,?,?,?,?,?)",(first_name, last_name, username, email, driver, hashed_pswd, salt))

		conn.commit()
		conn.close()

		try:
			params= {'username': username, 'initial_deposit': deposit}
			verify_url = f"{payments_url}/create_balance"
			response = requests.post(verify_url, data=params)
			if response.status_code != 200 or response.json().get('status') != 1:
				# Balance creation failed
				pass
		
		except Exception as e:
			pass

		return jsonify({'status': 1, "pass_hash": hashed_pswd})

	except Exception as e:
		conn.close()
		return jsonify({'status': 4, "pass_hash": "NULL"})




@app.route('/login', methods=(['POST']))
def login_user():
	
	conn = get_db()
	curr = conn.cursor()
	
	output = request.form
	username = output.get('username').strip()
	password = output.get('password')
	#salt = output.get('salt')

	if not all([username, password]):
		conn.close()
		return jsonify({'status': 2, "jwt": "NULL"})
	
	if username is None or password is None:
		conn.close()
		return jsonify({'status': 2, "jwt": "NULL"})

	try:
		curr.execute("SELECT password, salt FROM users WHERE username =?",(username,))
		the_pswd = curr.fetchone()
		if not the_pswd:
			conn.close()
			return jsonify({'status': 2, "jwt": "NULL"})

		pswd, salt = the_pswd
		hashed_pswd = hashing(password, salt)
		if hashed_pswd == pswd:
			conn.close()
			jwtoken = jwt_token(username)
			return jsonify({'status': 1, "jwt": jwtoken})
		
		else:
			conn.close()
			return jsonify({'status': 2, "jwt": "NULL"})
		
	except Exception as e:
		conn.close()
		return jsonify({'status': 2, "jwt": "NULL"})



@app.route('/rate', methods=(['POST']))
def rate_user():
	
	conn = get_db()
	curr = conn.cursor()
	
	output = request.form
	username = output.get('username').strip()
	rating = output.get('rating').strip()

	if not all([username, rating]):
		conn.close()
		return jsonify({'status': 2})

	try:
		rating = int(rating)
		if rating not in (0,1,2,3,4,5):
			conn.close()
			return jsonify({'status': 2})

	except Exception:
		conn.close()
		return jsonify({'status': 2})

	if not username:
		conn.close()
		return jsonify({'status': 2})

	try:
		rhead = request.headers
		auth_header = rhead.get('Authorization')
		
		if not auth_header:
			conn.close()
			return jsonify({'status': 2})
			
		if " " in auth_header:
			token = auth_header.split(" ")[1]
		else:
			token = auth_header
		
		auth_user = jwt_verification(token)
		if not auth_user:
			conn.close()
			return jsonify({'status': 2})

		if auth_user == username:
			conn.close()
			return jsonify({'status': 2})

		curr.execute("SELECT driver FROM users WHERE username = ?", (username,))
		user = curr.fetchone()
		if not user:
			conn.close()
			return jsonify({'status': 2})
		driver_target = user[0]


		curr.execute("SELECT driver FROM users WHERE username = ?", (auth_user,))
		driver_requestor = curr.fetchone()[0]


		if driver_target == driver_requestor:
			conn.close()
			return jsonify({'status': 2})
		
		if driver_requestor == 1: 
			Dusername = auth_user
			Pusername = username
		else:
			Dusername = username
			Pusername = auth_user


		try:
			params = {
				'Dusername': Dusername,
				'Pusername': Pusername,
				'status': 'confirmed'
			}
			
			verify_url = f'{reservations_url}/chk_reservation'
			response = requests.get(verify_url, params=params)
			
			if response.status_code != 200:
				conn.close()
				return jsonify({'status': 2})
			
			data = response.json()
			if not data.get('exists', False):
				conn.close()
				return jsonify({'status': 2})
				
		except requests.exceptions.RequestException as e:
			conn.close()
			return jsonify({'status': 2})
		
		

		curr.execute("INSERT INTO ratings (rater_username, rated_username, rating) VALUES (?, ?, ?)", (auth_user, username, rating))
		conn.commit()

		conn.close()
		return jsonify({'status': 1})

		
	except Exception as e:
		conn.close()
		return jsonify({'status': 2})




@app.route('/driver_status', methods=(['POST']))
def driver_status():
	
	conn = get_db()
	curr = conn.cursor()
	try:

		output = request.form
		username = output.get('username').strip()

		if not username:
			conn.close()
			return jsonify({'status': 2})
		
		curr.execute("SELECT driver FROM users WHERE username = ? AND driver = 1", (username,))
		user = curr.fetchone()
		conn.close()
		
		if user:
			return jsonify({'status': 1})
		
		else: 
			return jsonify({'status': 2})
		
	
	except Exception as e:
		conn.close()
		return jsonify({'status': 2})




@app.route('/passenger_status', methods=(['POST']))
def passenger_status():
	
	conn = get_db()
	curr = conn.cursor()
	try:

		output = request.form
		username = output.get('username').strip()

		if not username:
			conn.close()
			return jsonify({'status': 2})
		
		curr.execute("SELECT driver FROM users WHERE username = ? AND driver = 0", (username,))
		user = curr.fetchone()
		conn.close()
		
		if user:
			return jsonify({'status': 1})
		
		else: 
			return jsonify({'status': 2})
		
	
	except Exception as e:
		conn.close()
		return jsonify({'status': 2})		





@app.route('/driver_rating', methods=(['POST']))
def driver_rating():
	
	conn = get_db()
	curr = conn.cursor()
	try:

		output = request.form
		username = output.get('username').strip()
		
		if not username:
			conn.close()
			return jsonify({'rating': '0.00'})

		curr.execute("SELECT rating FROM ratings WHERE rated_username = ?", (username,))
		rate = curr.fetchall()
		conn.close()
		
		if rate:
			rating_val = [r[0] for r in rate]
			avg_rate = sum(rating_val) / len(rating_val)
			fmt_rate = f"{avg_rate:.2f}"
			return jsonify({'rating': fmt_rate})
		
		else:
			return jsonify({'rating': '0.00'})
	
	except Exception as e:
		conn.close()
		return jsonify({'rating': '0.00'})






@app.route('/clear', methods=['GET'])
def clear():
	global db_flag
	if os.path.exists(db_name):
		os.remove(db_name)
	db_flag = False
	return "Database Cleared"



if __name__ == '__main__':
	import requests
	app.run(host='0.0.0.0', port=5000, debug=True)












