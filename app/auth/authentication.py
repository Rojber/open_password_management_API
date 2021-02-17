from datetime import datetime
from flask import request, current_app, g
from bson import json_util
from base64 import b64decode
from app.mongoCli import create_csfle_client
from app.auth import auth
from app.tokenization import getToken
from app.auxiliaryFuncs import encryptAES


@auth.before_request
def before_request():
    g.db, g.client_encryption, g.data_key_id = create_csfle_client(current_app.config['MONGODB_CONNECTION_STRING'])

    # MANAGING RSA
    g.json = request.json
    js = b64decode(g.json['data'].encode('utf-8'))
    js = current_app.config['SERVER_DECRYPTOR'].decrypt(js)
    g.js = json_util.loads(js.decode('utf-8'))


@auth.teardown_request
def after_request(response):
    g.db.close()
    return response


@auth.route('/SignUp', methods=['POST'])
def signUp():
    check = g.db.passwordManager.accounts.find_one(
        {
            'login': g.client_encryption.encrypt(g.js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", g.data_key_id)
        }
    )
    if check is not None:
        return json_util.dumps({'response': 'LOGIN ALREADY USED'}), 400

    check = g.db.passwordManager.accounts.find_one(
        {
            'email': g.client_encryption.encrypt(g.js['email'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", g.data_key_id)
        }
    )
    if check is not None:
        return json_util.dumps({'response': 'EMAIL ALREADY USED'}), 400

    account = {
        'email': g.client_encryption.encrypt(g.js['email'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", g.data_key_id),
        'login': g.client_encryption.encrypt(g.js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", g.data_key_id),
        'password': g.client_encryption.encrypt(g.js['password'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random", g.data_key_id),
        'logindata': []
    }
    g.db.passwordManager.accounts.insert_one(account)
    return json_util.dumps({'response': 'OK'}), 201


@auth.route('/SignIn', methods=['POST'])
def singIn():
    result = None

    response = g.db.passwordManager.accounts.find_one(
        {
            'login': g.client_encryption.encrypt(g.js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", g.data_key_id),
        },
        {
            'password': 1,
            '_id': 1
        }
    )
    if response is None:
        return json_util.dumps({'response': 'NOT LOGGED IN'}), 401
    if response['password'] == g.js['password']:
        session = g.db.passwordManager.sessions.find_one(
            {
                '_id': response['_id']
            }
        )
        token = getToken()
        if session is None:
            session = {
                '_id': response['_id'],
                'token': token,
                'last_used': datetime.utcnow(),
                'public_key_PEM': g.json['public_key_PEM']
            }
            g.db.passwordManager.sessions.insert_one(session)
            result = token
        else:
            g.db.passwordManager.sessions.find_one_and_update(
                {
                    'token': session['token']
                },
                {
                    '$set':
                        {
                            'token': token,
                            'last_used': datetime.utcnow(),
                            'public_key_PEM': g.json['public_key_PEM']
                        }
                }
            )
            result = token
    else:
        return json_util.dumps({'response': 'NOT LOGGED IN'}), 401

    resp = {
        'response': result
    }
    resp = encryptAES(resp, g.json['public_key_PEM'])
    return json_util.dumps(resp), 200
