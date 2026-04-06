import sqlite3
import os
from flask import Flask, request, jsonify
import json
import hmac
import base64
import hashlib
import requests


app = Flask(__name__)
db_name = "reservations.db"
sql_file = "reservations.sql"
db_flag = False

user_url = "http://user:5000"
listings_url = "http://availability:5000"
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



@app.route('/reserve', methods=(['POST']))
def reserve():
	
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
		listingID = output.get('listingid')

		if not listingID:
			conn.close()
			return jsonify({'status': 3})


		#user as a passenger
		try:
			data= {'username': auth_user}
			verify_url = f"{user_url}/passenger_status"
			response = requests.post(verify_url, data=data)
			
			if response.status_code != 200:
				conn.close()
				return jsonify({'status': 3})
			
			data = response.json()
			if data.get('status') != 1:
				conn.close()
				return jsonify({'status': 3})

		except Exception as e:
			conn.close()
			return jsonify({'status': 3})
			

		
		#get list
		try:
			data= {'listingid': listingID}
			verify_url = f"{listings_url}/get_list"
			response = requests.post(verify_url, data=data)

			if response.status_code != 200:
				conn.close()
				return jsonify({'status': 3})

			data = response.json()
			if not data.get('exists', False):
				conn.close()
				return jsonify({'status': 3})

			
			Dusername = data.get('driver')
			price = data.get('price')
			day = data.get('day')

			if not all([Dusername, price, day]):
				conn.close()
				return jsonify({'status': 3})

		except Exception as e:
			conn.close()
			return jsonify({'status': 3})


		# balance with user as a passenger
		try:
			data= {'username': auth_user}
			verify_url = f"{payments_url}/get_balance"
			response = requests.post(verify_url, data=data)
			
			if response.status_code != 200:
				conn.close()
				return jsonify({'status': 3})
			
			data = response.json()
			data_balance = float((data.get('balance', '0')))

		except Exception as e:
			conn.close()
			return jsonify({'status': 3})
			

		
		flt_price = float(price)
		if data_balance < flt_price:
			conn.close()
			return jsonify({'status': 3})

		
		# transfer money to user as a driver
		try:
			data = {'Fuser': auth_user,
				'Tuser': Dusername,
				'amount': price}

			verify_url = f"{payments_url}/transfer"
			response = requests.post(verify_url, data=data, timeout=5)
			if response.status_code != 200:
				conn.close()
				return jsonify({'status': 3})
			
			data = response.json()
			if data.get('status') != 1:
				conn.close()
				return jsonify({'status': 3})
		
		except Exception as e:
			conn.close()
			return jsonify({'status': 3})


		# delete list
		try:
			data = {'listingid': listingID}
			verify_url = f"{listings_url}/del_list"
			response = requests.post(verify_url, data=data, timeout=5)
			
		except Exception as e:
			pass   #should still continue as payment is already done hence deletion fails


		curr.execute(
			"INSERT INTO reservations (listingID, Pusername, Dusername, price, day, status) VALUES (?, ?, ?, ?, ?, ?)",
			(listingID, auth_user, Dusername, price, day, 'confirmed')
		)
		conn.commit()
		
		#success
		conn.close()
		return jsonify({'status': 1})	

		
	except Exception as e:
		conn.close()
		return jsonify({'status': 3})






@app.route('/view', methods=(['GET']))
def view():
	
	conn = get_db()
	curr = conn.cursor()
	try:
		rhead = request.headers
		auth_header = rhead.get('Authorization')
		
		if not auth_header:
			conn.close()
			return jsonify({'status': 2, 'data': 'NULL'})
		
		if " " in auth_header:
			token = auth_header.split(" ")[1]
		else:
			token = auth_header
		
		auth_user = jwt_verification(token)
		if not auth_user:
			conn.close()
			return jsonify({'status': 2,'data': 'NULL'})

		#user a as driver?
		try:
			data={'username': auth_user}
			verify_url = f"{user_url}/driver_status"
			response = requests.post(verify_url, data=data)
			
			if response.status_code != 200:
				conn.close()
				return jsonify({'status': 2, 'data': 'NULL'})
			
			data = response.json()
			if data.get('status') == 1:
				is_driver = True
			else:
				is_driver = False
		
		except Exception as e:
			conn.close()
			return jsonify({'status': 2, 'data': 'NULL'})



		if is_driver == True:
			curr.execute('SELECT listingID, Pusername, price FROM reservations WHERE Dusername = ? ORDER BY reservationID DESC LIMIT 1',(auth_user,))
			info = curr.fetchone()

		else:
			curr.execute('SELECT listingID, Dusername, price FROM reservations WHERE Pusername = ? ORDER BY reservationID DESC LIMIT 1',(auth_user,))
			info = curr.fetchone()
		
		if not info:
			conn.close()
			return jsonify({'status': 2, 'data': 'NULL'})
		
		listingID = info[0]
		DoP_user = info[1]      #if requested is a Driver or Passenger
		price = info[2]

		try:
			data={'username': DoP_user}
			verify_url = f"{user_url}/driver_rating"
			response = requests.post(verify_url, data=data)
		
			if response.status_code == 200:
				data = response.json()
				data_rating = data.get('rating', '0.00')
			
			else:
				data_rating = "0.00"
		

		except Exception as e:
			data_rating = "0.00"
		

		obj =  {"listingid": int(listingID),
    		"price": f"{float(price):.2f}",
    		"user": DoP_user,
    		"rating": data_rating}
		
		#conn.commit()
		conn.close()
		return jsonify({'status': 1, 'data': obj})



	except Exception as e:
		conn.close()
		return jsonify({'status': 2, 'data': 'NULL'})




@app.route('/chk_reservation', methods=['GET'])
def chk_reservation():

    conn = get_db()
    curr = conn.cursor()
    
    try:
        Dusername = request.args.get('Dusername')
        Pusername = request.args.get('Pusername')
        
        if not all([Dusername, Pusername]):
            conn.close()
            return jsonify({'exists': False})
        
        curr.execute("SELECT * FROM reservations WHERE Dusername = ? AND Pusername = ? AND status = 'confirmed'",(Dusername, Pusername))
        res = curr.fetchone()
        conn.close()
        
        if res:
            return jsonify({'exists': True})
        else:
            return jsonify({'exists': False})
    
    except Exception as e:
        conn.close()
        return jsonify({'exists': False})





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