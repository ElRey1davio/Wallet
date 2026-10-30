import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()
database_url = os.environ.get("DATABASE_URL")


connections = psycopg2.connect(database_url)
cursor = connections.cursor()
cursor.execute("""
               CREATE TABLE users(
                   user_id SERIAL PRIMARY KEY,
                   name TEXT NOT NULL,
                   password_hash TEXT NOT NULL,
                   pin_hash TEXT NOT NULL,
                   balance NUMERIC(12,2) DEFAULT 0,
                   email TEXT UNIQUE NOT NULL
               );
               """)
connections.commit()
cursor.close()
connections.close()