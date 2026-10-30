import psycopg2
from dotenv import load_dotenv
import os

load_dotenv()
database_url = os.environ.get("DATABASE_URL")
connections = psycopg2.connect(database_url)
cursor = connections.cursor()
cursor.execute("""
               CREATE TABLE transactions(
                   transaction_id SERIAL PRIMARY KEY,
                   amount NUMERIC(12,2) NOT NULL,
                  user_id INTEGER REFERENCES users(user_id) NOT NULL,
                  type TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT NOW()
               );
               """)

connections.commit()
cursor.close()
connections.close()