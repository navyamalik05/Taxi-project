import sqlite3
import os
from flask import Flask, request, jsonify
import json
import hmac
import base64
import hashlib
import requests

app = Flask(__name__)
db_name = "aailability.db"
sql_file = "availability.sql"
db_flag = False

user_url = "http://user:5000"

'''
@app.route('/', methods=(['GET']))
def index():


	return json.dumps({'1': 'test', '2': 'test2'})

@app.route('/test_micro', methods=(['GET']))
def test_micro():

	return json.dumps({"response": "This is a message from Microservice 2"}) 
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




@app.route('/listing', methods=(['POST']))
def listing():
	
	conn = get_db()
	curr = conn.cursor()
	
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
		
		output = request.form
		listingid = output.get('listingid')
		day = output.get('day').strip()
		price = output.get('price').strip()

		if not all([listingid, day, price]):
			conn.close()
			return jsonify({'status': 2})
		
		#check if listingid is not empty.
		
		if day not in ('Monday', 'monday', 'Tuesday', 'tuesday', 'Wednesday', 'wednesday', 'Thursday', 'thursday', 'Friday', 'friday', 'Saturday', 'saturday', 'Sunday', 'sunday'):
			conn.close()
			return jsonify({'status': 2})
		
		flt_price = float(price)
		if flt_price < 0:
			conn.close()
			return jsonify({'status': 2})
    
		decimal = price.split('.')
		if len(decimal) == 2 and len(decimal[1]) > 2:
			conn.close()
			return jsonify({'status': 2})
		
		
		try:
			data={'username': auth_user}
			verify_url = f"{user_url}/driver_status"
			response = requests.post(verify_url, data=data)
			
			if response.status_code != 200:
				conn.close()
				return jsonify({'status': 2})
			
			data = response.json()
			if data.get('status') != 1:
				conn.close()
				return jsonify({'status': 2})

		except Exception:
			conn.close()
			return jsonify({'status': 2})


		curr.execute("SELECT listingid FROM listings WHERE listingid =?", (listingid,))
		ID = curr.fetchone()
		if ID:
			conn.close()
			return jsonify({'status': 2})
		
		curr.execute("INSERT INTO listings VALUES(?,?,?,?)", (listingid, auth_user, day, price))
		conn.commit()
		conn.close()
		return jsonify({'status': 1})
	
	except Exception as e:
		conn.close()
		return jsonify({'status': 2})


	


@app.route('/search', methods=(['GET']))
def search():
	
	conn = get_db()
	curr = conn.cursor()
	
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
		
		output = request.args
		day = output.get('day').strip()

		if not day:
			conn.close()
			return jsonify({'status': 2})

		if day not in ('Monday', 'monday', 'Tuesday', 'tuesday', 'Wednesday', 'wednesday', 'Thursday', 'thursday', 'Friday', 'friday', 'Saturday', 'saturday', 'Sunday', 'sunday'):
			conn.close()
			return jsonify({'status': 2})
		
		try:
			data={'username': auth_user}
			verify_url = f"{user_url}/passenger_status"
			response = requests.post(verify_url, data=data)
			
			if response.status_code != 200:
				conn.close()
				return jsonify({'status': 2})
			
			data = response.json()
			if data.get('status') != 1:
				conn.close()
				return jsonify({'status': 2})

		except Exception:
			conn.close()
			return jsonify({'status': 2})
		

		curr.execute("SELECT listingid, Dusername, price FROM listings WHERE day = ? ORDER BY price DESC",(day,))
		result = curr.fetchall()
		if not result:
			conn.close()
			return jsonify({'status': 1, 'data': []})
		

		array = []
		for r in result:
			try:
				data={'username': r[1]}
				verify_url = f"{user_url}/driver_rating"
				response = requests.post(verify_url, data=data)
			
				if response.status_code != 200:
					conn.close()
					return jsonify({'status': 2})
			
				data = response.json()
				Drating = data.get('rating', '0.00')
				fmt_price = f"{float(r[2]):.2f}"

				dic = {'listingid': int(r[0]), 'driver': r[1],  'price': fmt_price, 'rating': Drating}
				array.append(dic)

			except Exception:
				conn.close()
				return jsonify({'status': 2})
		

		conn.close()
		return jsonify({'status': 1, 'data': array})
		

	except Exception as e:
		conn.close()
		return jsonify({'status': 2})





@app.route('/get_list', methods=(['POST']))
def get_list():
	
	conn = get_db()
	curr = conn.cursor()
	try:

		output = request.form
		listingID = output.get('listingid')

		if not listingID:
			conn.close()
			return jsonify({'exists': False})
		
		curr.execute("SELECT Dusername, day, price FROM listings WHERE listingid = ?", (listingID,))
		data = curr.fetchone()
		conn.close()

		if data:
			Dusername = data[0]
			day = data[1]
			price = data[2]
			return jsonify({'exists': True, 'driver': Dusername, 'price': price, 'day': day})
		
		else:
			return jsonify({'exists': False})
	
	except Exception as e:
		conn.close()
		return jsonify({'exists': False})




@app.route('/del_list', methods=(['POST']))
def del_list():
	
	conn = get_db()
	curr = conn.cursor()
	try:

		output = request.form
		listingID = output.get('listingid')

		if not listingID:
			conn.close()
			return jsonify({'status': 2})
		
		curr.execute("DELETE FROM listings WHERE listingid = ?", (listingID,))
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