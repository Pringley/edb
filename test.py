"""Run tests on EDB."""

import shutil
import os.path
import tempfile

from unittest import TestCase, main
from edb import crypto, paillier, constants
from edb.client import Client

PASSPHRASE = b'hunter2 is not a good password'

class TestClient(TestCase):

    def setUp(self):
        self.client = Client()
    
    def test_encrypt(self):
        ptxt = b"test"
        ctxt = self.client.encrypt(ptxt)
        self.assertEqual(ptxt, self.client.decrypt(ctxt))

    def test_keyfile(self):
        keyinfo = crypto.generate_keyinfo(Client.KEY_SCHEMA)
        tmpdir = tempfile.mkdtemp()
        try:
            filename = os.path.join(tmpdir, '.keyinfo')
            crypto.write_keyinfo(keyinfo, filename)
            client = Client(filename)
            ptxt = b"test"
            ctxt = client.encrypt(ptxt)
            self.assertEqual(ptxt, client.decrypt(ctxt))
        finally:
            shutil.rmtree(tmpdir)

class TestCrypto(TestCase):

    def setUp(self):
        self.keyschema = {
            'encrypt': {'type': 'block', 'bits': 256},
            'hmac': {'type': 'block', 'bits': 256},
            'homomorphic': {'type': 'paillier', 'bits': 512},
        }
        self.keyinfo = crypto.generate_keyinfo(self.keyschema)

        # legacy
        self.names = ('foo', 'bar', 'baz')
        self.keys = crypto.generate_keys(PASSPHRASE, self.names)

    def test_key_generation(self):
        for name in self.names:
            key = self.keys[name]
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), constants.BLOCK_BYTES)

    def test_new_key_generation(self):
        self.assertIsInstance(self.keyinfo['encrypt'], bytes)
        self.assertIsInstance(self.keyinfo['hmac'], bytes)
        self.assertIsInstance(self.keyinfo['homomorphic'], paillier.Key)
        self.assertEqual(len(self.keyinfo['encrypt']), 256 // 8)
        self.assertEqual(len(self.keyinfo['hmac']), 256 // 8)

    def test_key_serialization(self):
        tmpdir = tempfile.mkdtemp()
        try:
            filename = os.path.join(tmpdir, '.keyinfo')
            crypto.write_keyinfo(self.keyinfo, filename)
            keyinfo2 = crypto.read_keyinfo(filename)
            for name, keydata in self.keyinfo.items():
                self.assertEqual(keydata, keyinfo2[name])
        finally:
            shutil.rmtree(tmpdir)

    def test_block_encrypt(self):
        key = self.keys['foo']
        message = b"7" * constants.BLOCK_BYTES
        ciphertext = crypto.encrypt(key, message)
        assert crypto.decrypt(key, ciphertext) == message

    def test_pseudorandom_generator(self):
        key = self.keys['foo']
        for index in range(10):
            block = crypto.prgenerator(key, index)
            self.assertIsInstance(block, bytes)
            self.assertEqual(len(block), constants.BLOCK_BYTES)

    def test_xor(self):
        test_block = b"t"  * constants.BLOCK_BYTES
        null_block = b"\0" * constants.BLOCK_BYTES
        self.assertEqual(crypto.xor(null_block, test_block), test_block)
        self.assertEqual(crypto.xor(test_block, test_block), null_block)

    def test_paillier(self):
        p = 293
        q = 433
        g = 6497955158
        mu = 53022
        n = p*q
        lmb = 31536 # lcm(p-1, q-1)
        key = paillier.Key(n, g, lmb, mu)
        public = key.public()

        # test private key encrypt(decrypt(x)) == x
        ptxt_original = 521
        ctxt = paillier.encrypt(key, ptxt_original)
        ptxt = paillier.decrypt(key, ctxt)
        self.assertEqual(ptxt_original, ptxt)

        # test public key encrypt(decrypt(x)) == x
        ctxt = paillier.encrypt(public, ptxt_original)
        ptxt = paillier.decrypt(key, ctxt)
        self.assertEqual(ptxt_original, ptxt)

        # test homomorphism
        ptxt1 = 14
        ptxt2 = 19
        ctxt1 = paillier.encrypt(public, ptxt1)
        ctxt2 = paillier.encrypt(public, ptxt2)
        final_ptxt = paillier.decrypt(key, ctxt1 * ctxt2)
        self.assertEqual(final_ptxt, ptxt1 + ptxt2)

    def test_paillier_key_generation(self):
        key = paillier.generate_keys(bits = 128)
        public = key.public()

        ptxt_original = 521
        ctxt = paillier.encrypt(public, ptxt_original)
        ptxt = paillier.decrypt(key, ctxt)
        self.assertEqual(ptxt_original, ptxt)

        # test homomorphism
        ptxt1 = 14
        ptxt2 = 19
        ctxt1 = paillier.encrypt(public, ptxt1)
        ctxt2 = paillier.encrypt(public, ptxt2)
        final_ptxt = paillier.decrypt(key, ctxt1 * ctxt2)
        self.assertEqual(final_ptxt, ptxt1 + ptxt2)

        # test average
        ptxt3 = 12
        ctxt3 = paillier.encrypt(public, ptxt3)
        ciphertext = [ctxt1, ctxt2, ctxt3]
        numerator, denominator = paillier.average(public, ciphertext)
        numerator = paillier.decrypt(key, numerator)
        denominator = paillier.decrypt(key, denominator)
        average = numerator/denominator
        self.assertAlmostEqual(average, 15)

if __name__ == '__main__':
    main()
