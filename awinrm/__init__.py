from __future__ import unicode_literals
import logging
logger = logging.getLogger('awinrm')
handler = logging.StreamHandler()
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False


import re
from base64 import b64encode
import xml.etree.ElementTree as ET
import warnings
import asyncio


from asysocks.unicomm.protocol.client.http.commons.factory import HTTPConnectionFactory
from awinrm.protocol import Protocol


class Session:
	def __init__(self, url:str, ssl_ctx = None, authtype='auto', factory:HTTPConnectionFactory = None, **kwargs):
		if factory is None:
			if url is None:
				raise Exception('Either url or factory parameter is required')
			factory = HTTPConnectionFactory.from_url(url)
		cred = factory.get_credential()
		target = factory.get_target()
		self.url = self._build_url(target.get_url(), kwargs.get('transport', 'plaintext'))
		self.protocol = Protocol(self.url, cred, ssl_ctx = ssl_ctx, authtype=authtype, proxies=target.proxies, **kwargs)
		self.__shells = []

	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc, tb):
		for shell in self.__shells:
			await shell.close()
		await self.protocol.close()

	def create_shell(self, working_directory=None, env_vars=None, noprofile=False,
					codepage=437, lifetime=None, idle_timeout=None):
		shell = WinRMShell(self, working_directory=working_directory, env_vars=env_vars, noprofile=noprofile,
					codepage=codepage, lifetime=lifetime, idle_timeout=idle_timeout)
		self.__shells.append(shell)
		return shell

	async def run_cmd(self, command, args=()):
		shell_id = await self.protocol.open_shell()
		command_id = await self.protocol.run_command(shell_id, command, args)
		stdout_buff = b''
		stderr_buff = b''
		return_code = -1
		async for stdout, stderr, return_code in self.protocol.get_command_output(shell_id, command_id):
			stdout_buff += stdout
			stderr_buff += stderr
			return_code = return_code
		await self.protocol.cleanup_command(shell_id, command_id)
		await self.protocol.close_shell(shell_id)
		return stdout_buff, stderr_buff, return_code

	async def run_ps(self, script):
		"""base64 encodes a Powershell script and executes the powershell
		encoded script command
		"""
		# must use utf16 little endian on windows
		encoded_ps = b64encode(script.encode('utf_16_le')).decode('ascii')
		rs = self.run_cmd('powershell -encodedcommand {0}'.format(encoded_ps))
		if len(rs.std_err):
			# if there was an error message, clean it it up and make it human
			# readable
			rs.std_err = self._clean_error_msg(rs.std_err)
		return rs

	def _clean_error_msg(self, msg):
		"""converts a Powershell CLIXML message to a more human readable string
		"""
		# TODO prepare unit test, beautify code
		# if the msg does not start with this, return it as is
		if msg.startswith(b"#< CLIXML\r\n"):
			# for proper xml, we need to remove the CLIXML part
			# (the first line)
			msg_xml = msg[11:]
			try:
				# remove the namespaces from the xml for easier processing
				msg_xml = self._strip_namespace(msg_xml)
				root = ET.fromstring(msg_xml)
				# the S node is the error message, find all S nodes
				nodes = root.findall("./S")
				new_msg = ""
				for s in nodes:
					# append error msg string to result, also
					# the hex chars represent CRLF so we replace with newline
					new_msg += s.text.replace("_x000D__x000A_", "\n")
			except Exception as e:
				# if any of the above fails, the msg was not true xml
				# print a warning and return the original string
				warnings.warn(
					"There was a problem converting the Powershell error "
					"message: %s" % (e))
			else:
				# if new_msg was populated, that's our error message
				# otherwise the original error message will be used
				if len(new_msg):
					# remove leading and trailing whitespace while we are here
					return new_msg.strip().encode('utf-8')

		# either failed to decode CLIXML or there was nothing to decode
		# just return the original message
		return msg

	def _strip_namespace(self, xml):
		"""strips any namespaces from an xml string"""
		p = re.compile(b"xmlns=*[\"\"][^\"\"]*[\"\"]")
		allmatches = p.finditer(xml)
		for match in allmatches:
			xml = xml.replace(match.group(), b"")
		return xml

	@staticmethod
	def _build_url(target, transport):
		match = re.match(
			r'(?i)^((?P<scheme>http[s]?)://)?(?P<host>[0-9a-z-_.]+)(:(?P<port>\d+))?(?P<path>(/)?(wsman)?)?', target)  # NOQA
		scheme = match.group('scheme')
		if not scheme:
			# TODO do we have anything other than HTTP/HTTPS
			scheme = 'https' if transport == 'ssl' else 'http'
		host = match.group('host')
		port = match.group('port')
		if not port:
			port = 5986 if transport == 'ssl' else 5985
		path = match.group('path')
		if not path:
			path = 'wsman'
		return '{0}://{1}:{2}/{3}'.format(scheme, host, port, path.lstrip('/'))



class WinRMShell:
	def __init__(self, session:Session, working_directory:str=None, env_vars=None, noprofile:bool=False,
				codepage:int=437, lifetime:int=None, idle_timeout:int=None):
		self.session = session
		self.working_directory = working_directory
		self.env_vars = env_vars
		self.noprofile = noprofile
		self.codepage = codepage
		self.lifetime = lifetime
		self.idle_timeout = idle_timeout
		self.shell_cmd = 'cmd.exe'
		self.command_id = None
		self.closed_evt = asyncio.Event()

		self.shell_id = None
		self.stdin = asyncio.Queue()
		self.stdout = asyncio.Queue()
		self.stderr = asyncio.Queue()
		self.return_code = None

	async def __aenter__(self):
		try:
			self.shell_id = await self.session.protocol.open_shell(
				working_directory = self.working_directory,
				env_vars = self.env_vars,
				noprofile = self.noprofile,
				codepage = self.codepage,
				lifetime = self.lifetime,
				idle_timeout = self.idle_timeout
			)
			self.command_id = await self.session.protocol.run_command(self.shell_id, self.shell_cmd)
			stdout, stderr, return_code, command_done = await self.session.protocol._raw_get_command_output(self.shell_id, self.command_id)
			await self.stdout.put(stdout)
			await self.stderr.put(stderr)
			self.return_code = return_code

			return self
		except Exception as e:
			await self.__aexit__(None, None, None)
			raise e
	
	async def __aexit__(self, exc_type, exc, tb):
		await self.close()

	async def close(self):
		if self.closed_evt.is_set():
			return
		await self.session.protocol.cleanup_command(self.shell_id, self.command_id)
		await self.session.protocol.close_shell(self.shell_id)
		self.closed_evt.set()

	async def send_input(self, data):
		await self.session.protocol.send_command_input(self.shell_id, self.command_id, data)
		await self.read_output()

	async def read_output(self):
		stdout, stderr, return_code, command_done = await self.session.protocol._raw_get_command_output(self.shell_id, self.command_id)
		await self.stdout.put(stdout)
		await self.stderr.put(stderr)
		self.return_code = return_code


def decode_bytes(data:bytes, hint:str='cp437'):
	encodings = ['utf-8', 'cp1252', 'cp1251', 'cp932', 'cp936']
	if hint is not None and len(hint) > 0:
		encodings.insert(0, hint)
	for encoding in encodings:
		try:
			return data.decode(encoding)
		except UnicodeDecodeError:
			continue
	raise UnicodeDecodeError("Unable to decode the input data with the provided encodings.")
