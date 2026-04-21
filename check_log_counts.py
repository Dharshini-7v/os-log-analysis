
import asyncio
import aiomysql
import yaml
from pathlib import Path

async def check():
    config = yaml.safe_load(open('config/default.yaml'))
    db = config['database']['mysql']
    conn = await aiomysql.connect(host=db['host'], user=db['username'], password=db['password'], db=db['database'])
    curr = await conn.cursor()
    
    await curr.execute('SELECT COUNT(*) FROM logs')
    log_count = await curr.fetchone()
    print(f"LOGS COUNT: {log_count[0]}")
    
    await curr.execute('SELECT COUNT(*) FROM log_templates')
    template_count = await curr.fetchone()
    print(f"TEMPLATES COUNT: {template_count[0]}")
    
    conn.close()

if __name__ == "__main__":
    asyncio.run(check())
