from flask import current_app
from testAuxiliaryFuncs import decryptAES, getDecryptor, encryptAES
from bson import json_util, ObjectId


def test_allsites(client, auth, app):
    token = auth.login('test1', 'test1')

    response = client.get('/api/AllSites', headers={"token": token})

    with app.app_context():
        response = decryptAES(json_util.loads(response.data), getDecryptor(current_app.rsa_private))

    response = json_util.dumps(response)

    # check if both sites are returned
    assert "test_login_site1.com" in response
    assert "test_login_site2.com" in response

    # check if endpoint returns id of LoginData
    assert "_id" in response


def test_get_logindata(client, auth, app):
    token = auth.login('test1', 'test1')

    response = client.get('/api/AllSites', headers={"token": token})

    with app.app_context():
        response = decryptAES(json_util.loads(response.data), getDecryptor(current_app.rsa_private))

    response = client.get('/api/LoginData/' + str(response[1]['_id']), headers={"token": token})

    with app.app_context():
        response = decryptAES(json_util.loads(response.data), getDecryptor(current_app.rsa_private))

    # check if proper user credentials are returned
    assert response['login'] == 'test_login2'
    assert response['password'] == 'test_password2'


def test_post_logindata(client, auth, app):
    token = auth.login('test1', 'test1')

    js = {
        "site": "post_test.com",
        "login": "post_test_login",
        "password": "post_test_passwd",
        "note": "post_test_note"
    }

    with app.app_context():
        response = client.post('/api/LoginData', json=encryptAES(js, current_app.server_key_pem),
                               headers={"token": token})

        # check response status code
        assert response.status_code == 201

        check = current_app.db.passwordManager.accounts.find_one(
            {
                'login': current_app.client_encryption.encrypt("test1", "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                               current_app.data_key_id),
                'logindata.site': js['site']
            },
            {
                '_id': 0,
                'logindata.$': 1
            }
        )
        check = check['logindata'][0]

    # check if login date has been updated
    assert js.items() <= check.items()


def test_put_logindata(client, auth, app):
    token = auth.login('test1', 'test1')

    response = client.get('/api/AllSites', headers={"token": token})

    with app.app_context():
        response = decryptAES(json_util.loads(response.data), getDecryptor(current_app.rsa_private))
        logindata_id = str(response[1]['_id'])

        js = {
            "site": "put_test.com",
            "login": "put_test_login",
            "password": "put_test_passwd",
            "note": "put_test_note"
        }

        response = client.put('/api/LoginData/' + logindata_id,
                              json=encryptAES(js, current_app.server_key_pem),
                              headers={"token": token})

        # check response status code
        assert response.status_code == 201

        check = current_app.db.passwordManager.accounts.find_one(
            {
                'login': current_app.client_encryption.encrypt("test1", "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                               current_app.data_key_id),
                'logindata._id': ObjectId(logindata_id)
            },
            {
                '_id': 0,
                'logindata.$': 1
            }
        )

    check = check['logindata'][0]

    # check if login date has been updated
    assert js.items() <= check.items()


def test_delete_logindata(client, auth, app):
    token = auth.login('test1', 'test1')

    response = client.get('/api/AllSites', headers={"token": token})

    with app.app_context():
        response = decryptAES(json_util.loads(response.data), getDecryptor(current_app.rsa_private))
        logindata_id = str(response[1]['_id'])

    response = client.delete('/api/LoginData/' + logindata_id, headers={"token": token})

    # check response status code
    assert response.status_code == 200

    # check if logindata record has been deleted from db
    with app.app_context():
        assert (
                current_app.db.passwordManager.accounts.find_one(
                    {
                        'login': current_app.client_encryption.encrypt("test1",
                                                                       "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                                       current_app.data_key_id),
                        'logindata._id': ObjectId(logindata_id)
                    }
                )
                is None
        )


def test_backup(client, auth, app):
    token = auth.login('test1', 'test1')

    response = client.get('/api/Backup', headers={"token": token})

    # check response status code
    assert response.status_code == 200

    with app.app_context():
        response = decryptAES(json_util.loads(response.data), getDecryptor(current_app.rsa_private))

        check = current_app.db.passwordManager.accounts.find_one(
            {
                'login': current_app.client_encryption.encrypt("test1", "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                               current_app.data_key_id)
            },
            {
                '_id': 0,
                'logindata': 1
            }
        )

    # check if proper data has been returned
    assert check['logindata'] == response
