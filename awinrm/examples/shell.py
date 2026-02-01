import sys
import asyncio
from awinrm import Session, decode_bytes
from awinrm import logger
from awinrm.exceptions import ShellTerminatedError

import aioconsole


async def print_output(shell, stop_event):
	"""Print shell output until stop event is set."""
	while not stop_event.is_set():
		try:
			# Use timeout to check stop_event periodically
			try:
				stdout = await asyncio.wait_for(shell.stdout.get(), timeout=0.1)
				if len(stdout) > 0:
					print(decode_bytes(stdout), end='', flush=True)
			except asyncio.TimeoutError:
				pass
			
			try:
				stderr = await asyncio.wait_for(shell.stderr.get(), timeout=0.1)
				if len(stderr) > 0:
					print(decode_bytes(stderr), end='', file=sys.stderr, flush=True)
			except asyncio.TimeoutError:
				pass
				
		except asyncio.CancelledError:
			break


async def amain(url, authtype, shell_type):
	async with Session(url, authtype=authtype) as session:
		async with session.create_shell(shell_type=shell_type) as shell:
			stop_event = asyncio.Event()
			output_task = asyncio.create_task(print_output(shell, stop_event))
			
			try:
				while not shell.is_terminated:
					try:
						user_input = await aioconsole.ainput("")
						await shell.send_input((user_input + '\r\n').encode())
					except ShellTerminatedError as e:
						# Shell has terminated - this is normal when user types 'exit'
						print(f'\n[*] Shell terminated (exit code: {e.exit_code})')
						break
					except EOFError:
						# Ctrl+D - close the shell
						print('\n[*] Closing shell...')
						break
			except asyncio.CancelledError:
				pass
			finally:
				# Stop the output task
				stop_event.set()
				output_task.cancel()
				try:
					await output_task
				except asyncio.CancelledError:
					pass
	

def main():
	import argparse
	import logging
	from asyauth import logger as authlogger

	parser = argparse.ArgumentParser(description='WinRM - Interactive remote shell')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity')
	parser.add_argument('-a', '--authproto', choices=['spnego', 'credssp'], default='spnego', help='Authentication protocol to use')
	parser.add_argument('-s', '--shell', choices=['cmd', 'powershell', 'pwsh'], default='powershell', help='Shell type (default: powershell)')
	parser.add_argument('url', type=str, help='URL to connect to')
	args = parser.parse_args()

	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
		logger.setLevel(logging.ERROR)
		authlogger.setLevel(logging.ERROR)
	else:
		logging.basicConfig(level=logging.DEBUG)
		logger.setLevel(logging.DEBUG)
		authlogger.setLevel(logging.DEBUG)
	
	asyncio.run(amain(args.url, args.authproto, args.shell))


if __name__ == '__main__':
	main()
