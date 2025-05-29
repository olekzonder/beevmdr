import asyncpg
import asyncio

async def connect_db():
    return await asyncpg.connect(
    user='postgres', 
    password='postgres', 
    database='monitor.db', 
    host='127.0.0.1')

async def check_hash_exists(sha256):
    conn = await connect_db()
    result = await conn.fetch('SELECT 1 FROM main.hashes WHERE sha256 = $1', sha256)
    await conn.close()
    return len(result) > 0

async def add_hash(sha256):
    conn = await connect_db()
    await conn.execute('INSERT INTO main.hashes (sha256) VALUES ($1)', sha256)
    await conn.close()

