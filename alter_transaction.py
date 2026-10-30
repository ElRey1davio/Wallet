import psycopg2
import os
from dotenv import load_dotenv        
        
load_dotenv()
database_url = os.environ.get("DATABASE_URL")
        
connections = psycopg2.connect(database_url)
cursor = connections.cursor()
cursor.execute("""
               ALTER TABLE transactions ADD column reference TEXT UNIQUE;
               ALTER TABLE transactions ADD COLUMN status TEXT DEFAULT 'pending'
                       ;""")

connections.commit()
cursor.close()
connections.close()