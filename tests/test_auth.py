import pytest
from flask import current_app
from testAuxiliaryFuncs import get_encrypted_login
from bson import json_util


def test_register(client, app):
    js = {"email": "test_case@test.com", "login": "test_case", "password": "testtest"}
    with app.app_context():
        js = get_encrypted_login(current_app.server_key_pem, js)
        js = {"data": js, "public_key_PEM": current_app.rsa_public.exportKey().decode('utf-8')}

    response = client.post('/api/SignUp', json=js)
    js = json_util.loads(response.data)

    # check if response is OK
    assert js['response'] == 'OK'

    # test that the user was inserted into the database
    with app.app_context():
        assert (
                current_app.db.passwordManager.accounts.find_one(
                    {
                        'login': current_app.client_encryption.encrypt("test_case",
                                                                       "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                                       current_app.data_key_id)
                    }
                )
                is not None
        )


@pytest.mark.parametrize(
    ("email", "login", "password", "message"),
    (
        ("test1@test.com", "a", "b", b'{"response": "EMAIL ALREADY USED"}'),
        ("a@test.com", "test1", "b", b'{"response": "LOGIN ALREADY USED"}')
    )
)
def test_register_validate_input(client, app, email, login, password, message):
    js = {"email": email, "login": login, "password": password}
    with app.app_context():
        js = get_encrypted_login(current_app.server_key_pem, js)
        js = {"data": js, "public_key_PEM": current_app.rsa_public.exportKey().decode('utf-8')}

    response = client.post('/api/SignUp', json=js)
    assert message in response.data


def test_login(auth, app):
    # test that successful login returns session token
    token = auth.login("test1", "test1")
    assert token is not None

    # check if user session is stored in database
    with app.app_context():
        assert (
                current_app.db.passwordManager.sessions.find_one(
                    {
                        'token': token
                    }
                )
                is not None
        )


@pytest.mark.parametrize(
    ("login", "password", "message"),
    (
        ("test1", "wrong_password", "NOT LOGGED IN"),
        ("wrong_login", "test1", "NOT LOGGED IN")
    )
)
def test_login_validate_input(auth, login, password, message):
    print(login)
    print(password)
    response = auth.login(login, password)
    assert message in response


def test_logout(client, auth, app):
    token = auth.login("test1", "test1")

    # check if user session is deleted from db
    with client and app.app_context():
        auth.logout(token)
        assert(
                current_app.db.passwordManager.sessions.find_one(
                    {
                        'token': token
                    }
                )
                is None
        )
