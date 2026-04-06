import sqlite3
import os
from flask import Flask, request, jsonify
import json
import hmac
import base64
import hashlib
import requests


app = Flask(__name__)
#might not need this?
db_name = "payments.db"
sql_file = "payments.sql"
db_flag = False

user_url = "http://user:5000"


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
	return conn



@app.route('/', methods=(['GET']))
def index():
	conn = get_db()
	cursor = conn.cursor()
	cursor.execute("SELECT * FROM test;")
	output = cursor.fetchall()
	conn.close()

	return output



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



@app.route('/add', methods=(['POST']))
def add():
	
	conn = get_db()
	curr = conn.cursor()
	
	try:
		rhead = request.headers
		auth_header = rhead.get('Authorization')
		
		if not auth_header:
			return jsonify({'status': 2})
		
		if " " in auth_header:
			token = auth_header.split(" ")[1]
		else:
			token = auth_header
		
		auth_user = jwt_verification(token)
		if not auth_user:
			return jsonify({'status': 2})


		output = request.form
		amount = output.get('amount').strip()

		if not amount:
			return jsonify({'status': 2})
		
		try:
			flt_amt = float(amount)
			if flt_amt <= 0:
				return jsonify({'status': 2})

			decimal = amount.split('.')
			if len(decimal) == 2 and len(decimal[1]) > 2:
				return jsonify({'status': 2})

			curr.execute("UPDATE balances SET balance = balance + ? WHERE username = ?", (flt_amt, auth_user))
			conn.commit()
			conn.close()
			
			return jsonify({'status': 1})
		

		except Exception as e:
			conn.close()
			return  jsonify({'status': 2})


	except Exception as e:
		conn.close()
		return  jsonify({'status': 2})




@app.route('/view', methods=(['GET']))
def view():

	conn = get_db()
	curr = conn.cursor()
	
	try:
		rhead = request.headers
		auth_header = rhead.get('Authorization')
		
		if not auth_header:
			return jsonify({"status": 2, "balance": "NULL"})
		
		if " " in auth_header:
			token = auth_header.split(" ")[1]
		else:
			token = auth_header
		
		auth_user = jwt_verification(token)
		if not auth_user:
			return jsonify({"status": 2, "balance": "NULL"})


		curr.execute("SELECT balance FROM balances WHERE username = ?", (auth_user,))
		result = curr.fetchone()
		conn.close()
		
		if result:
			fmt_balance = f"{float(result[0]):.2f}"
			return jsonify({"status": 1, "balance": fmt_balance})
		
		else:
			return jsonify({"status": 2, "balance": "NULL"})
	
	except Exception as e:
		conn.close()
		return jsonify({"status": 2, "balance": "NULL"})


		




@app.route('/transfer', methods=(['POST']))
def transfer():
	
	conn = sqlite3.connect(db_name)
	curr = conn.cursor()
	try:

		output = request.form
		Fuser = output.get('Fuser').strip()
		Tuser = output.get('Tuser').strip()
		amount = output.get('amount')

		if not all([Fuser, Tuser, amount]):
			conn.close()
			return jsonify({'status': 2})
		
		flt_amt = float(amount)
		if flt_amt <= 0:
			conn.close()
			return jsonify({'status': 2})

		curr.execute("SELECT balance FROM balances WHERE username = ?", (Fuser,))
		dept = curr.fetchone()
		if not dept:
			conn.close()
			return jsonify({'status': 2})
		
		bal = float(dept[0])

		if bal <flt_amt:
			conn.close()
			return jsonify({'status': 2})

		#cut money from passengers and add to drivers
		curr.execute("UPDATE balances SET balance = balance - ? WHERE username = ?", (flt_amt, Fuser))
		curr.execute("UPDATE balances SET balance = balance + ? WHERE username = ?", (flt_amt, Tuser))
		conn.commit()
		conn.close()
		
		return jsonify({'status': 1})

	except Exception as e:
			conn.close()
			return jsonify({'status': 2})



	



@app.route('/create_balance', methods=(['POST']))
def create_balance():
	
	conn = get_db()
	curr = conn.cursor()
	try:

		output = request.form
		username = output.get('username').strip()
		bal = output.get('initial_deposit', '0.00')
		flt_bal = float(bal)

		if not username:
			conn.close()
			return jsonify({'status': 2})
		
		curr.execute("INSERT INTO balances (username, balance) VALUES (?, ?)", (username, flt_bal))
		conn.commit()
		conn.close()
		return jsonify({'status': 1})

	
	except Exception as e:
		conn.close()
		return jsonify({'status': 2})





@app.route('/get_balance', methods=(['POST']))
def get_balance():
	
	conn = get_db()
	curr = conn.cursor()
	try:

		output = request.form
		username = output.get('username').strip()
		
		if not username:
			conn.close()
			return jsonify({'balance': '0.00'})
		
		curr.execute("SELECT balance FROM balances WHERE username = ?", (username,))
		res = curr.fetchone()
		conn.close()

		if res:
			return jsonify({'balance': str(res[0])})
		
		else:
			return jsonify({'balance': '0.00'})

	
	except Exception as e:
		conn.close()
		return jsonify({'balance': '0.00'})




@app.route('/update_balance', methods=(['POST']))
def update_balance():
	
	conn = get_db()
	curr = conn.cursor()
	try:

		output = request.form
		username = output.get('username').strip()
		amt = output.get('amount')
		flt_amt = float(amt)
		
		if not all([username, amt]):
			conn.close()
			return jsonify({'status': 2})
		
		curr.execute("UPDATE balances SET balance = balance + ? WHERE username = ?", (flt_amt, username))
		conn.commit()
		conn.close()
		return jsonify({'status': 1})

	
	except Exception as e:
		conn.close()
		return jsonify({'status': 2})










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