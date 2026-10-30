from flask import Flask, jsonify, request , redirect , session
import psycopg2
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import jwt, datetime
import uuid
from decimal import Decimal, InvalidOperation
import hmac
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from urllib.parse import urlencode


load_dotenv()
database_url = os.environ.get("DATABASE_URL")
secret_key = os.environ.get("SECRET_KEY")
payment_link = os.environ.get("PAYMENT_LINK")
webhook_secret = os.environ.get("WEBHOOK_SECRET")
github_client_id = os.environ.get("GITHUB_CLIENT_ID")
github_client_secret = os.environ.get("GITHUB_CLIENT_SECRET")
github_redirect_uri = os.environ.get("GITHUB_REDIRECT_URI")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("wallet.log"), 
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("wallet")


app = Flask(__name__)
app.secret_key = secret_key
limiter = Limiter(get_remote_address, app=app)

@app.after_request
def log_request(response):
    logger.info(f"{request.method} {request.path} -> {response.status_code} ip={request.remote_addr}")
    return response

def get_user_key():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return f"user:{payload['user_id']}"
    except (jwt.InvalidTokenError, KeyError):
        return get_remote_address()

@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded for IP: {request.remote_addr} on {request.path}")
    return {"status": "failure", "message": "Too many attempts. Try again later."}, 429

@app.route("/register" , methods = ["POST"])
@limiter.limit("5 per minute")
def register():
    
    result = request.get_json(silent=True)
    if result is None:
        return {"status": "failure", "message": "data is empty"}, 400
    fields = ["name", "email", "password", "pin"]
    missing = []
    for field in fields:
        if not result.get(field):
            missing.append(field)
    if missing:         
            return {"status": "failure", "message": f"Missing fields: {missing}"}, 400
    
    name = result.get('name')
    email = result.get('email')
    password = result.get('password')
    password_hash = generate_password_hash(password)
    pin = str(result.get('pin', ''))
    if not pin.isdigit():
        return {"status":"failure", "message":"Pin should be a digit"}, 400
    if len(pin) != 4:
        return {"status":"failure", "message":"Pin should be 4 digits"}, 400 #?
    pin_hash = generate_password_hash(pin)
    
    connections = None #this is incase the connect crashes so the finally won't crash 
    cursor = None
    try:
        connections = psycopg2.connect(database_url)
        cursor = connections.cursor()
        cursor.execute("""
                       INSERT INTO users (name, password_hash, pin_hash, email )
                       VALUES (%s,%s,%s,%s);   
                       """, (name,password_hash,pin_hash, email))
        connections.commit()
        return {"status":"success" , "message":"User registered"}, 201

    except psycopg2.OperationalError:
        logger.error(f"Database unreachable: OperationalError on {request.path}")
        return {"status":"failure", "message":"Gateway Server Timeout"}, 504
    except psycopg2.errors.UniqueViolation:
        return {"status":"failure","message":"Email already used"}, 409
    finally:
        if cursor:
            cursor.close()
        if connections:
            connections.close()
            

@app.route("/login", methods = ["POST"])
@limiter.limit("5 per minute")

def login():
    data = request.get_json(silent=True)
    if data is None:
        return {"status": "failure", "message": "data is empty"}, 400
    fields = [ "email", "password"]
    missing = []
    for field in fields:
        if not data.get(field):
            missing.append(field)
    if missing:
        return {"status":"failure" , "message":f"{missing} not found"},400
    
    
    email = data.get('email')
    password = data.get('password')
    
    
    
    cursor = None
    connections = None
    try:
        connections = psycopg2.connect(database_url)
        cursor = connections.cursor()
        cursor.execute("""
                       SELECT user_id, password_hash FROM users WHERE email = %s
                      ;""" , (email,))
        
        result = cursor.fetchone()
        
        if result:
            passwordhash = result[1]
        else:
            logger.warning(f"Login failed: unknown email ip={request.remote_addr}")
            return {"status":"failure" , "message":"Incorrect email or password" },401
        
        
        if passwordhash is None:
            logger.warning(f"Password login on account without password user_id={result[0]}")
            return {"status":"failure" , "message":"Incorrect email or password"}, 401
        
        
        
        check_password = check_password_hash(passwordhash,password)
        if not check_password:
            logger.warning(f"Failed login attempt for email: {email}")
            return {"status":"failure" , "message":"Incorrect email or password"}, 401
        
        else:
            now = datetime.datetime.now(datetime.timezone.utc)
            expiry = now + datetime.timedelta(minutes=30)
            payload = {"user_id": result[0], "exp": expiry}
            token = jwt.encode(payload, secret_key, algorithm="HS256")
            
            logger.info(f"Login success user_id={result[0]}")
            
            return {"status": "success", "token": token}, 200
            
             
        
    except psycopg2.OperationalError:
        logger.error(f"Database unreachable: OperationalError on {request.path}")
        return {"status":"failure" , "message":"Gateway Server Timeout"}, 504
    finally:
        if cursor:
            cursor.close()
        if connections:
            connections.close()
            
 





@app.route("/auth/github")
def github_login():
    state = uuid.uuid4().hex
    session["oauth_state"] = state
    params = urlencode({
        "client_id": github_client_id,
        "redirect_uri": github_redirect_uri,
        "scope": "user:email",
        "state": state,
    })
    return redirect(f"https://github.com/login/oauth/authorize?{params}")


@app.route("/auth/github/callback")
def github_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code or state != session.pop("oauth_state", None):
        return {"status": "failure", "message": "Invalid OAuth state"}, 400

    token_res = requests.post(
        "https://github.com/login/oauth/access_token",
        data={
            "client_id": github_client_id,
            "client_secret": github_client_secret,
            "code": code,
            "redirect_uri": github_redirect_uri,
        },
        headers={"Accept": "application/json"},
        timeout=10,
    )
    access_token = token_res.json().get("access_token")
    if not access_token:
        return {"status": "failure", "message": "GitHub sign-in failed"}, 401

    gh_headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
    }
    profile = requests.get("https://api.github.com/user", headers=gh_headers, timeout=10).json()
    emails = requests.get("https://api.github.com/user/emails", headers=gh_headers, timeout=10).json()

    email = None
    if isinstance(emails, list):
        email = next((e["email"] for e in emails if e.get("primary") and e.get("verified")), None)
    if not email:
        return {"status": "failure", "message": "No verified GitHub email found"}, 400
    name = profile.get("name") or profile.get("login") or "GitHub user"

    connections = None
    cursor = None
    try:
        connections = psycopg2.connect(database_url)
        cursor = connections.cursor()
        cursor.execute("SELECT user_id FROM users WHERE email = %s;", (email,))
        row = cursor.fetchone()
        if row:
            user_id = row[0]
        else:
            cursor.execute(
                "INSERT INTO users (name, email) VALUES (%s, %s) RETURNING user_id;",
                (name, email),
            )
            user_id = cursor.fetchone()[0]
            connections.commit()

        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
        token = jwt.encode({"user_id": user_id, "exp": expiry}, secret_key, algorithm="HS256")
        logger.info(f"GitHub login success user_id={user_id}")
        return {"status": "success", "token": token}, 200

    except psycopg2.OperationalError:
        logger.error(f"Database unreachable: OperationalError on {request.path}")
        return {"status": "failure", "message": "Gateway Server Timeout"}, 504
    finally:
        if cursor:
            cursor.close()
        if connections:
            connections.close()


 



            
@app.route("/balance" , methods = ["GET"])
def balance():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    
    
    if not auth_header:
        return {"status":"failure" , "message":"Please login"}, 401 
    
    
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
         
    except jwt.ExpiredSignatureError:
        return {"status":"failure" , "message":"Token Expired"}, 401
    except jwt.InvalidTokenError:
        return {"status":"failure", "message":"Invalid Token"}, 401
    
    connections = None
    cursor = None
    try:
        user_id = payload["user_id"]
        connections = psycopg2.connect(database_url)
        cursor = connections.cursor()
        cursor.execute("""
                       SELECT balance FROM users WHERE user_id = %s;
                       """, (user_id,))
        result = cursor.fetchone()
        if not result:
            return {"status":"failure" , "message":"User not found ?"},404
        else:
            balance = result[0]
            return {"status":"success", "balance":balance},200
    except psycopg2.OperationalError:
        logger.error(f"Database unreachable: OperationalError on {request.path}")
        return {"status":"failure" , "message":"Gateway Server Timeout"}, 504
    
    finally:
        if cursor:
            cursor.close()
            
        if connections:
            connections.close()
            
@app.route("/deposit/initiate" , methods = ["POST"])
def deposit():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    
    if not auth_header:
            return {"status":"failure" , "message":"Please login"}, 401 
        
        
    try:
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
            
    except jwt.ExpiredSignatureError:
                    return {"status":"failure" , "message":"Token Expired"}, 401
    except jwt.InvalidTokenError:
                    return {"status":"failure", "message":"Invalid Token"}, 401
     
     
    data = request.get_json(silent=True)
    if data is None:
        return {"status": "failure", "message": "data is empty"}, 400
    fields = ["amount"]
    missing = []
    for field in fields:
            if not data.get(field):
                missing.append(field)
    if missing:
            return {"status":"failure" , "message":f"{missing} not found"},400
         
    raw_amount = data.get("amount")
    try:
       amount = Decimal(str(raw_amount))
          
    except (InvalidOperation, ValueError,TypeError):
        return {"status":"failure" , "message":"amount must be a valid number"}, 400
    
    if amount <= 0:
        return {"status":"failure" , "message":"amount must be greater than 0"}, 400
            
    
    reference = uuid.uuid4().hex
                
    connections = None
    cursor = None
    try:
        user_id = payload["user_id"]
        connections = psycopg2.connect(database_url)
        cursor = connections.cursor()
        cursor.execute("""
                       INSERT INTO transactions (user_id, type, amount,reference,status)
                       VALUES (%s, 'deposit' , %s,%s, 'pending');
                       """,(user_id,amount, reference))
        connections.commit()
        
        return {"status":"success","reference": reference, "payment_link":f"{payment_link}?reference={reference}"},201
    except psycopg2.OperationalError:
        logger.error(f"Database unreachable: OperationalError on {request.path}")
        return {"status":"failure" , "message":"Gateway Server Timeout"}, 504
    
    finally:
        if cursor:
            cursor.close()
            
        if connections:
            connections.close()
  
@app.route("/webhook/payment" , methods = ["POST"])
def payment_webhook():
    webhook_header = request.headers.get('X-Webhook-Secret', '')
    if not webhook_secret or not webhook_header:
        return {"status":"failure" , "message":"NotAuthorized"},401
    
    compare = hmac.compare_digest(webhook_secret,webhook_header)
    if not compare:
        return {"status":"failure" , "message":"NotAuthorized(invalidwebhok signature)"}, 401
    
    
    data = request.get_json(silent=True)
    if data is None:
        return {"status":"failure", "message":"data is empty"},400
    fields = ["reference", "status"]
    missing = []
    for field in fields:
                if not data.get(field):
                    missing.append(field)
    if missing:
                return {"status":"failure" , "message":f"{missing} not found"},400
             
    reference = data["reference"]
    provider_status = data["status"]
    
    
    connections = None
    cursor = None
    try:
        connections = psycopg2.connect(database_url)
        cursor = connections.cursor()
        cursor.execute("""
                       SELECT user_id, amount,status FROM transactions WHERE reference = %s;
                       """, (reference,))
        
        result = cursor.fetchone()
        if not result:
            return {"status":"failure" , "message":"User not found ?"},404
        
        db_status = result[2]
        if db_status != "pending":
            logger.info(f"Idempotency check: ignored duplicate webhook for reference={reference}")
            return {"status":"success"},200
        #explain the double credit protection
        
        if provider_status == "success":
            amount = result[1]
            user_id = result[0]

            cursor.execute("""
                           UPDATE transactions SET status = 'success'
                           WHERE reference = %s AND status = 'pending';
                           """, (reference,))

            if cursor.rowcount == 0:
                logger.info(f"Idempotency: already processed reference={reference}")
                return {"status": "success"}, 200

            cursor.execute("""
                           UPDATE users SET balance = balance + %s
                           WHERE user_id = %s;
                           """, (amount, user_id))

        else:
            cursor.execute("""
                           UPDATE transactions SET status = 'failed'
                           WHERE reference = %s AND status = 'pending';
                           """, (reference,))

        connections.commit()
        logger.info(f"Webhook processed: reference={reference}, provider_status={provider_status}")
        return {"status":"success"},200
        
    except psycopg2.OperationalError:
        logger.error(f"Database unreachable: OperationalError on {request.path}")
        return {"status":"failure" , "message":"Gateway Server Timeout"},504
    
    finally:
        if cursor:
            cursor.close()
        if connections:
            connections.close()
        
            
 
@app.route("/withdraw", methods = ["POST"])
@limiter.limit("5 per minute", key_func=get_user_key)
def withdraw():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ','').strip()
    
    
    if not auth_header:
                return {"status":"failure" , "message":"Please login"}, 401 
            
            
    try:
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
            
    except jwt.ExpiredSignatureError:
                    return {"status":"failure" , "message":"Token Expired"}, 401
    except jwt.InvalidTokenError:
                    return {"status":"failure", "message":"Invalid Token"}, 401
        
    
    
    data = request.get_json(silent=True)
    if data is None:
            return {"status":"failure", "message":"data is empty"},400
    fields = ["amount" , "pin"]
    missing = []
    for field in fields:
        if not data.get(field):
             missing.append(field)
    if missing:
        return {"status":"failure" , "message":f"{missing} not found"},400
                
    raw_amount = data["amount"]
    #pin = data["pin"]
    

    try:
        amount = Decimal(str(raw_amount))
            
    except (InvalidOperation, ValueError,TypeError):
        return {"status":"failure" , "message":"amount must be a valid number"}, 400
    
    if amount <= 0:
        return {"status":"failure" , "message":"amount must be greater than 0"}, 400
            
    
    pin = str(data.get('pin'))
    if not re.match(r'^\d{4}$', pin):
        return {"status": "failure", "message": "PIN must be exactly 4 digits"}, 400

    connections = None
    cursor = None
    try:
        user_id = payload["user_id"]
        if not user_id:
            return {"status":"failure", "message":"user not found"},401
        
        connections = psycopg2.connect(database_url)
        cursor = connections.cursor()
        cursor.execute("""
                       SELECT user_id, balance, pin_hash FROM users WHERE user_id = %s
                       ;""",(user_id,))
        result = cursor.fetchone()
        if not result:
            return {"status":"failure", "message":"User not found"}, 404
        
        if result[2] is None:
            return {"status":"failure", "message":"Set a PIN before withdrawing"}, 403

        pin_check = check_password_hash(result[2], pin)
        if not pin_check:
            logger.warning(f"Wrong PIN attempt user_id={user_id}")
            return {"status":"failure" , "message":"Incorrect Pin"},401
        if result[1] < amount:
            return {"status":"failure", "message":"Insufficient funds"}, 400
        
        reference = uuid.uuid4().hex
        
        cursor.execute("""
                       UPDATE users SET balance = balance - %s WHERE user_id = %s AND balance >= %s;
                       """, (amount,user_id,amount))
        
        if cursor.rowcount == 0:
            return {"status":"failure", "message":"Insufficient funds or user not found"},400
        elif cursor.rowcount == 1:
            cursor.execute("""
                        INSERT INTO transactions (user_id, type, amount, reference, status)
                                                VALUES (%s , 'withdrawal', %s,%s,'success');
                                                
                        """,(user_id,amount,reference))    
            
        connections.commit()
        
        cursor.execute("""SELECT balance FROM users WHERE user_id = %s
                               ;""" , (user_id,))
        info = cursor.fetchone()
        if not info:
            return {"status":"failure", "message":"user not found"},404
        else:
            balance = info[0]
            logger.info(f"Withdrawal successful: user_id={user_id}, amount={amount}, ref={reference}")
            return {"status":"success", "reference":reference, "balance":balance },200
    
    
    except psycopg2.OperationalError:
        logger.error(f"Database unreachable: OperationalError on {request.path}")
        return {"status":"failure", "message":"Gateway Server Timeout"}, 504
    finally:
        
        if cursor:
                    cursor.close()
                
        if connections:
            connections.close()
        
@app.route("/transactions", methods = ["GET"])
def get_transactions():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    
    if not auth_header:
        return {"status":"failure" , "message":"please login"},401
    
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
            
    except jwt.ExpiredSignatureError:
                    return {"status":"failure" , "message":"Token Expired"}, 401
    except jwt.InvalidTokenError:
                    return {"status":"failure", "message":"Invalid Token"}, 401
        
    user_id = payload["user_id"]
    page = request.args.get("page",1, type = int)
    limit = request.args.get("limit", 10, type = int)
    
    if page <1 or limit <1:
        return {"status":"failure", "message":"page and limit must be 1 or more"},400#dont know what the message should be 
    if limit > 100:
        limit = 100
        
    offset = (page -1) * limit
    
    connections = None
    cursor = None
    try:
        connections = psycopg2.connect(database_url)
        cursor = connections.cursor()
        cursor.execute("""
                       SELECT COUNT(*) FROM transactions WHERE user_id = %s;
                       """, (user_id,))
        data = cursor.fetchone()
        count = data[0]
        
        cursor.execute("""
                       SELECT reference, type, amount, status,created_at FROM transactions 
                                              WHERE user_id = %s
                                              ORDER by created_at DESC
                                              LIMIT %s OFFSET %s;
                       """,(user_id,limit,offset))
    
        results = cursor.fetchall()
        items = []
        
        for row in results:
            items.append({"reference": row[0],"type":row[1], "amount": str(row[2]), "status":row[3], "created_at":str(row[4])})
        return {
    "status": "success",
    "transactions": items,
    "page": page,
    "limit": limit,
    "total_count": count
}, 200
        
    except psycopg2.OperationalError:
        logger.error(f"Database unreachable: OperationalError on {request.path}")
        return {"status":"failure", "message":"Gateway Server Timeout"},504
    finally:
        if cursor:
            cursor.close()
        
        if connections:
            connections.close()
        

        
        
    
        
        
if __name__ ==("__main__") :
    app.run(debug = True)