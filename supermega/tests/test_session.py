import unittest
import hashlib
import os
import random
from StringIO import StringIO

from .. import Session, User, File
from .. import errors

USERNAME = os.environ.get('MEGA_USERNAME', None)
PASSWORD = os.environ.get('MEGA_PASSWORD', None)

def random_string(length):
	return (('%0'+str(length)+'x') % random.randrange(256**(length/2)))[:length]

def calculate_hash(string):
	hash = hashlib.sha256()
	hash.update(string)
	return hash.hexdigest()

def verify_hash(file, chunks, obj, sha256):
	hash = hashlib.sha256()
	for chunk in chunks:
		hash.update(chunk)
	obj.assertEqual(hash.hexdigest(), sha256)

requires_account = unittest.skipUnless(USERNAME and PASSWORD,
	"MEGA_USERNAME or MEGA_PASSWORD missing")

class TestSession(unittest.TestCase):
	def setUp(self):
		self.sess = Session()

	def test_public_file_download(self):
		url = 'https://mega.co.nz/#!2ctGgQAI!AkJMowjRiXVcSrRLn3d-e1vl47ZxZEK0CbrHGIKFY-E'
		sha256 = '9431103cb989f2913cbc503767015ca22c0ae40942932186c59ffe6d6a69830d'

		self.sess.download(verify_hash, url, self, sha256)

	def test_ephemeral_account(self):
		sess = Session.ephemeral()
		sess.datastore # This triggers lazy-loading the datastore

	def test_key_derivation(self):
		self.assertEqual(User.derive_key("password"), 'd\x039r^n\xbd\x13\xa2_\x00R\x12\x9f|\xb1')

	@requires_account
	def test_create_from_env(self):
		s = Session.from_env()

	@requires_account
	def test_print_tree(self):
		self.sess.login(USERNAME, PASSWORD)
		self.sess.root.print_tree()

class TestFile(unittest.TestCase):
	def setUp(self):
		self.sess = Session(USERNAME, PASSWORD)
		self.random_filename = random_string(5)

	def tearDown(self):
		try:
			f = self.sess.root[self.random_filename]
			f.delete()
		except KeyError, errors.ObjectNotFound:
			pass

	@requires_account
	def test_file_upload_download(self):
		length = random.randint(120, 400) * 0x400
		contents = chr(random.randint(0,256)) * length
		sha256 = calculate_hash(contents)
		fileobj = StringIO(contents)

		uploaded_file = File.upload(self.sess.root, fileobj,
			name=self.random_filename, size=length)

		uploaded_file.download(verify_hash, self, sha256)
