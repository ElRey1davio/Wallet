import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()
database_url = os.environ.get("DATABASE_URL")

connections = psycopg2.connect(database_url)
cursor = connections.cursor()
cursor.execute("""
               CREATE INDEX IF NOT EXISTS idx_transactions_user_created
               ON transactions (user_id, created_at DESC);
               """)
connections.commit()
cursor.close()
connections.close()