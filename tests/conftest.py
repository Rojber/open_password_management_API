from flask import current_app
import pytest
from app import create_app, mongoCli
from testPopulateDatabase import populate
from testAuxiliaryFuncs import getRSAKeys, getEncryptor, decryptAES, getDecryptor
from Crypto.PublicKey import RSA
from bson import json_util
from base64 import b64encode


@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # create the app with common test config
    app = create_app('testing')

    # create the database and load test data
    with app.app_context():
        # drop and populate db with fresh 20 accounts
        mongoCli.drop_database(current_app.config['MONGODB_CONNECTION_STRING'])
        current_app.db, current_app.client_encryption, current_app.data_key_id = mongoCli.create_csfle_client(current_app.config['MONGODB_CONNECTION_STRING'])
        populate(current_app.db, current_app.client_encryption, current_app.data_key_id)

        # generate client RSA keys
        current_app.rsa_public, current_app.rsa_private = getRSAKeys()

        # get client public RSA key in PEM format
        response = app.test_client().get('/api/GetPublicKey')
        current_app.server_key_pem = response.data

    yield app

    # close db client connection
    with app.app_context():
        current_app.db.close()


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


class AuthActions(object):
    def __init__(self, client, rsa_public, rsa_private):
        self._client = client
        self.rsa_public = rsa_public
        self.rsa_private = rsa_private

    def login(self, username="test", password="test"):
        response = self._client.get('/api/GetPublicKey')
        server_key_pem = response.data
        js = {"login": username, "password": password}
        js = self.get_encrypted_login(server_key_pem, js)
        js = {"data": js, "public_key_PEM": self.rsa_public.exportKey().decode('utf-8')}

        response = self._client.post('/api/SignIn', json=js)
        js = json_util.loads(response.data)

        if response.status_code == 200:
            js = decryptAES(js, getDecryptor(self.rsa_private))

        return js['response']

    def logout(self, token):
        return self._client.get("/api/LogOut", headers={"token": token})

    @staticmethod
    def get_encrypted_login(pub_key, jss):
        server_encryptor = getEncryptor(RSA.importKey(pub_key))
        jss = server_encryptor.encrypt(json_util.dumps(jss).encode('utf-8'))
        jss = b64encode(jss).decode('utf-8')
        return jss


@pytest.fixture
def auth(client, app):
    with app.app_context():
        return AuthActions(client, current_app.rsa_public, current_app.rsa_private)
