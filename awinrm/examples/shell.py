import sys
import asyncio
import traceback
from awinrm import Session, decode_bytes
from awinrm import logger

import aioconsole

async def print_output(shell):
	while True:
		try:
			stdout = await shell.stdout.get()
			if len(stdout) > 0:
				print(decode_bytes(stdout), end='')
			stderr = await shell.stderr.get()
			if len(stderr) > 0:
				print(decode_bytes(stderr), end='', file=sys.stderr)
		except asyncio.CancelledError:
			break
		except Exception as e:
			traceback.print_exc()
			print('[-] Error: %s' % str(e))
			sys.exit(1)

async def amain(url, authtype):
	async with Session(url, authtype=authtype) as session:
		async with session.create_shell() as shell:
			try:
				x = asyncio.create_task(print_output(shell))
				while True:
					user_input = await aioconsole.ainput("")
					await shell.send_input(user_input + '\r\n')
			except Exception as e:
				traceback.print_exc()
				print('[-] Error: %s' % str(e))
				sys.exit(1)
	

def main():
	import argparse
	import logging
	from asyauth import logger as authlogger

	parser = argparse.ArgumentParser(description='WinRM - Execute a single shell command remotely')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity')
	parser.add_argument('-a', '--authproto', choices=['spnego', 'credssp'], default = 'spnego', help = 'Authentication protocol to use')
	parser.add_argument('url', type=str, help = 'URL to connect to')
	args = parser.parse_args()

	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
		logger.setLevel(logging.ERROR)
		authlogger.setLevel(logging.ERROR)
	else:
		logging.basicConfig(level=logging.DEBUG)
		logger.setLevel(logging.DEBUG)
		authlogger.setLevel(logging.DEBUG)
	
	asyncio.run(amain(args.url, args.authproto))

if __name__ == '__main__':
	main()