from awinrm.protocol import Protocol
from awinrm import Session
from asysocks.unicomm.protocol.client.http.commons.factory import HTTPConnectionFactory

# Please do not use this, it will change in the future
class AWinRMSessionFactory:
	def __init__(self, target, credential, authtype='auto', httpfactory:HTTPConnectionFactory = None):
		self.target = target
		self.credential = credential
		self.httpfactory = httpfactory
		self.authtype = authtype
		if self.authtype not in ['auto', 'credssp', 'spnego']:
			raise Exception('Invalid authtype! Must be one of auto, credssp, spnego')
	
	def get_connection(self):
		# helper to follow other factori APIs
		return self.get_session()

	def get_session(self):
		return Session(None, ssl_ctx = None, authtype=self.authtype, factory = self.httpfactory)