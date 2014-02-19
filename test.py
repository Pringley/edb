"""Run tests on EDB."""

from unittest import TestCase, main

from edb import crypto, constants, Client, Server

PASSPHRASE = b'hunter2 is not a good password'

class TestServer(TestCase):

    def setUp(self):
        self.client = Client(PASSPHRASE)
        self.server = Server()

        # populate server with encrypted words
        words = [b'apple', b'banana', b'strawberry']
        for index, word in enumerate(words):
            ciphertext = self.client.encrypt_word(index, word)
            self.server.add_word(ciphertext)

    def test_search(self):
        # client computes encrypted word and its search key
        search_word = b'banana'
        preword, word_key = self.client.search_parameters(search_word)

        # server replies with matching ciphertexts
        results = self.server.search(preword, word_key)

        # client decrypts results
        plaintexts = [self.client.decrypt_word(index, ciphertext)
                      for index, ciphertext in results]
        self.assertIn(search_word, plaintexts)

class TestClient(TestCase):

    def setUp(self):
        self.client = Client(PASSPHRASE)
    
    def test_encrypt(self):
        index = 3
        word = b"test"
        ciphertext = self.client.encrypt_word(index, word)
        self.assertEqual(self.client.decrypt_word(index, ciphertext), word)

class TestCrypto(TestCase):

    def setUp(self):
        self.names = ('foo', 'bar', 'baz')
        self.keys = crypto.generate_keys(PASSPHRASE, self.names)

    def test_key_generation(self):
        for name in self.names:
            key = self.keys[name]
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), constants.BLOCK_BYTES)

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

if __name__ == '__main__':
    main()
