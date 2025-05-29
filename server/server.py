import asyncio
from aiohttp import web
import ssl
import os
from db_helper import check_hash_exists, add_hash

SSL_CERTIFICATE = 'cert.pem'
SSL_PRIVATE_KEY = 'key.pem'
hashs_path = 'malware_hashes.txt'

async def background_task():
    while True:
        # Пример новых хешей, которые мы можем получать, например, из файла или API
        if os.path.exists(hashs_path):
            new_hashes = []
            with open(hashs_path,'r') as file:
                for hash in file:
                    exists = await check_hash_exists(hash)
                    if not exists:
                        await add_hash(hash)
                        new_hashes.append(hash)
                
        await asyncio.sleep(10) 

async def init_app():
    app = web.Application()
    return app

server_address = 'localhost'
server_port = 8080

async def main():
    asyncio.create_task(background_task())

    app = await init_app()
    
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(SSL_CERTIFICATE, keyfile=SSL_PRIVATE_KEY)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, server_address, server_port, ssl_context=ssl_context)
    await site.start()

    while True:
        await asyncio.sleep(3600)

asyncio.run(main())
