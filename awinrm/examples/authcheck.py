import asyncio
from awinrm import Session
from asysocks.unicomm.protocol.client.http.client import ClientSession

async def check_auth(url):
	async with ClientSession() as session:
		async with session.post(url) as resp:
			if resp.status == 401:
				return resp.get_all('www-authenticate', [])
			return ['NOAUTH']

async def amain(url):
	transport = 'ssl'
	if url.startswith('http://'):
		transport = 'plaintext'
	url = Session._build_url(url, transport)
	print('[+] Testing URL: ' + url)
	headers = await check_auth(url)
	for entry in headers:
		print('[+] Authenthod: %s' % entry)


def main():
	import argparse

	parser = argparse.ArgumentParser(description='WinRM - Enumerate authentication types supported by the remote server')
	parser.add_argument('url', type=str, help = 'URL to connect to. Must start with http:// or https://')
	args = parser.parse_args()
	
	asyncio.run(amain(args.url))

if __name__ == '__main__':
	main()