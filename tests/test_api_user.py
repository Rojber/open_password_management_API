from flask import current_app
from testAuxiliaryFuncs import decryptAES, getDecryptor, encryptAES
from bson import json_util, ObjectId


def test_get_user(client, auth, app):
    token = auth.login('test2', 'test2')

    response = client.get('/api/User', headers={"token": token})

    # check response status code
    assert response.status_code == 200

    with app.app_context():
        response = decryptAES(json_util.loads(response.data), getDecryptor(current_app.rsa_private))

    # check if proper user info is returned
    assert response['login'] == 'test2'
    assert response['email'] == 'test2@test.com'


def test_put_user(client, auth, app):
    token = auth.login('test1', 'test1')

    js = {
        "email": "put_test@test.com",
        "login": "put_test_login",
        "password": "put_test_passwd",
    }

    with app.app_context():
        response = client.put('/api/User', json=encryptAES(js, current_app.server_key_pem), headers={"token": token})

        # check response status code
        assert response.status_code == 201

        # check if user login has been changed
        assert (
            current_app.db.passwordManager.accounts.find_one(
                {
                    'login': current_app.client_encryption.encrypt("test1",
                                                                   "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                                   current_app.data_key_id)
                }
            ) is None
        )

        check = current_app.db.passwordManager.accounts.find_one(
            {
                'login': current_app.client_encryption.encrypt("put_test_login", "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                               current_app.data_key_id)
            },
            {
                '_id': 0,
                'login': 1,
                'email': 1,
                'password': 1
            }
        )

    # check if login data has been updated
    assert js.items() <= check.items()


def test_delete_user(client, auth, app):
    token = auth.login('test1', 'test1')

    response = client.delete('/api/User', headers={"token": token})

    # check response status code
    assert response.status_code == 200

    # check if user has been deleted from db
    with app.app_context():
        assert (
                current_app.db.passwordManager.accounts.find_one(
                    {
                        'login': current_app.client_encryption.encrypt("test1",
                                                                       "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                                       current_app.data_key_id)
                    }
                )
                is None
        )
