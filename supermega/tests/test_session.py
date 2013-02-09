import unittest
import hashlib

from .. import Session
from .. import models

class TestSession(unittest.TestCase):
	def setUp(self):
		self.sess = Session()

	def test_public_file_download(self):
		url = 'https://mega.co.nz/#!2ctGgQAI!AkJMowjRiXVcSrRLn3d-e1vl47ZxZEK0CbrHGIKFY-E'
		sha256 = '9431103cb989f2913cbc503767015ca22c0ae40942932186c59ffe6d6a69830d'

		hash = hashlib.sha256()

		def verify_hash(file, chunks):
			for chunk in chunks:
				hash.update(chunk)

			self.assertEqual(hash.hexdigest(), sha256)

		self.sess.download(verify_hash, url)

	def test_ephemeral_account(self):
		sess = self.sess

		user = models.User(sess)
		user.ephemeral()

		sess.init_datastore()

	def test_key_derivation(self):
		self.assertEqual(models.User.derive_key("password"), 'd\x039r^n\xbd\x13\xa2_\x00R\x12\x9f|\xb1')
