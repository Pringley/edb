import requests

from edb.client import Client as EDBClient

class Client(EDBClient):

    def __init__(self, passphrase, host=None, port=None):
        super(self.__class__, self).__init__(passphrase)
        self.host = host or 'localhost'
        self.port = port or 8000
        self.url = 'http://{}:{}/'.format(self.host, self.port)
        self.packet_url = self.url + 'packets/'

    def search(self, **query):
        encrypted_query = self.encrypt_query(query)
        resp = requests.get(self.packet_url, params=encrypted_query)
        return [self.decrypt_model(model, paillier_fields=['length'],
                exclude_fields=['id'])
                for model in resp.json()]

    def create(self, **model):
        encrypted_model = self.encrypt_model(model, paillier_fields=['length'])
        requests.post(self.packet_url, data=encrypted_model)
