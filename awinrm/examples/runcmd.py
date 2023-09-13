import sys
import asyncio
import traceback
from awinrm import Session, decode_bytes
from awinrm import logger

async def amain(url, command, authtype):
	async with Session(url, authtype=authtype) as session:
		try:
			stdout, stderr, return_code = await session.run_cmd(command)
			if len(stdout) > 0:
				print(decode_bytes(stdout))
			if len(stderr) > 0:
				print(decode_bytes(stderr), file=sys.stderr)
			sys.exit(return_code)
		except Exception as e:
			traceback.print_exc()
			print('[-] Error: %s' % str(e))
			sys.exit(1)

def main():
	import argparse
	import logging
	from asyauth import logger as authlogger
	from asysocks import logger as sockslogger

	parser = argparse.ArgumentParser(description='WinRM - Execute a single shell command remotely')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity')
	parser.add_argument('-c', '--command', type=str, default = 'ipconfig /all', help = 'Shell command to execute')
	parser.add_argument('-a', '--authproto', choices=['spnego', 'credssp'], default = 'spnego', help = 'Authentication protocol to use')
	parser.add_argument('url', type=str, help = 'URL to connect to')
	args = parser.parse_args()

	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
		logger.setLevel(logging.ERROR)
		authlogger.setLevel(logging.ERROR)
		sockslogger.setLevel(logging.ERROR)
	else:
		logging.basicConfig(level=logging.DEBUG)
		logger.setLevel(logging.DEBUG)
		authlogger.setLevel(logging.DEBUG)
		sockslogger.setLevel(logging.DEBUG)
	
	asyncio.run(amain(args.url, args.command, args.authproto))

if __name__ == '__main__':
	main()