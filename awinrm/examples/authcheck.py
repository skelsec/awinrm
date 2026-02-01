import asyncio
import httpx
from awinrm import Session


async def check_auth(url):
    async with httpx.AsyncClient() as client:
        response = await client.post(url, content=b'')
        if response.status_code == 401:
            www_auth = response.headers.get('www-authenticate', '')
            # Parse multiple auth methods from the header
            return [part.strip().split()[0] for part in www_auth.split(',') if part.strip()]
        return ['NOAUTH']


async def amain(url):
    transport = 'ssl'
    if url.startswith('http://'):
        transport = 'plaintext'
    url = Session._build_url(url, transport)
    print('[+] Testing URL: ' + url)
    headers = await check_auth(url)
    for entry in headers:
        print('[+] Auth method: %s' % entry)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='WinRM - Enumerate authentication types supported by the remote server'
    )
    parser.add_argument('url', type=str, help='URL to connect to. Must start with http:// or https://')
    args = parser.parse_args()

    asyncio.run(amain(args.url))


if __name__ == '__main__':
    main()
