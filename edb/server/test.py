from django.test import TestCase

from edb.client import Client
from edb.server.models import _Ping

class EncryptedModelTestCase(TestCase):

    def setUp(self):
        self.client = Client(b"hunter2 is not a good passphrase")
        self.ip1_ptxt = b'127.0.0.1'
        self.ip2_ptxt = b'128.66.0.0'
        self.ip3_ptxt = b'192.0.2.0'
        self.ip1 = self.client.encrypt(self.ip1_ptxt)
        self.ip2 = self.client.encrypt(self.ip2_ptxt)
        self.ip3 = self.client.encrypt(self.ip3_ptxt)
        _Ping.objects.create(source=self.ip1, destination=self.ip2)
        _Ping.objects.create(source=self.ip1, destination=self.ip3)
        _Ping.objects.create(source=self.ip2, destination=self.ip3)

    def test_encrypted_filter(self):
        query = self.client.query(self.ip1_ptxt)
        results = _Ping.objects.encrypted_filter(source=query)

        self.assertEqual(2, len(results))
        dests = [result.destination for result in results]
        self.assertIn(self.ip2, dests)
        self.assertIn(self.ip3, dests)
