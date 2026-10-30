import psycopg2 
import os
from dotenv import load_dotenv

load_dotenv()
database_url = os.environ.get("DATABASE_URL")

connections = psycopg2.connect(database_url)
cursor = connections.cursor()
cursor.execute("""
    ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ALTER COLUMN pin_hash DROP NOT NULL;
""")