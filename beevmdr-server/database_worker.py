import psycopg2
from psycopg2 import sql
from typing import List, Dict, Optional
import re

class DatabaseManager:
    def __init__(self, config: dict):
        self.config = config
    
    def _get_connection(self):
        return psycopg2.connect(**self.config)
    
    def find_events_by_keywords(self, keywords: List[str]) -> List[Dict]:
        conn = self._get_connection()
        try:
            with conn.cursor() as cursor:
                query = sql.SQL("""
                    SELECT id, timestamp, endpoint, filename, task_name
                    FROM events
                    WHERE filename ~* %s
                    ORDER BY timestamp DESC
                """)
                pattern = '|'.join(re.escape(keyword) for keyword in keywords)
                cursor.execute(query, (pattern,))
                
                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        finally:
            conn.close()

    def get_all_events(self) -> List[Dict]:
        conn = self._get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT id, timestamp, endpoint, filename, task_name
                    FROM events
                    ORDER BY timestamp DESC
                """)
                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        finally:
            conn.close()
