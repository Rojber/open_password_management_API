from flask import request, current_app, g
from bson import json_util, ObjectId
from app.tokenization import checkToken
from app.mongoCli import create_csfle_client
from app.api import api
from app import auxiliaryFuncs


@api.before_request
def before_request():
    g.db, g.client_encryption, g.data_key_id = create_csfle_client(current_app.config['MONGODB_CONNECTION_STRING'])

    outcome, g.userID, g.userKeyPEM = checkToken(request.headers['token'], g.db)
    if outcome == 1:
        return json_util.dumps({'response': 'WRONG TOKEN'}), 401
    if outcome == 2:
        return json_util.dumps({'response': 'SESSION EXPIRED'}), 401


@api.teardown_request
def after_request(response):
    g.db.close()
    return response


@api.route('/LoginData/<loginID>', methods=['GET', 'PUT', 'DELETE'])
def manageLoginData(loginID):
    if request.method == 'GET':
        response = g.db.passwordManager.accounts.find_one(
            {
                '_id': ObjectId(g.userID),
            },
            {
                'logindata': 1
            }
        )

        for tup in response['logindata']:
            if tup['_id'] == ObjectId(loginID):
                response = tup
                break

        return json_util.dumps(auxiliaryFuncs.encryptAES(response, g.userKeyPEM)), 200

    if request.method == 'PUT':
        js = request.json
        js = auxiliaryFuncs.decryptAES(js, current_app.config['SERVER_DECRYPTOR'])

        js['passwordStrength'] = auxiliaryFuncs.measurePasswordStrength(js['password'])
        logindat = {
            "_id": ObjectId(loginID),
            'site': js['site'],
            'login': g.client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random", g.data_key_id),
            'password': g.client_encryption.encrypt(js['password'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random", g.data_key_id),
            'passwordStrength': js['passwordStrength'],
            'note': js['note']
        }
        g.db.passwordManager.accounts.find_one_and_update(
            {
                '_id': ObjectId(g.userID), 'logindata._id': ObjectId(loginID)
            },
            {
                '$set':
                    {
                        "logindata.$": logindat
                    }
            }
        )
        return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, g.userKeyPEM)), 201

    if request.method == 'DELETE':
        g.db.passwordManager.accounts.find_one_and_update(
            {
                '_id': ObjectId(g.userID)
            },
            {
                '$pull':
                    {
                        'logindata':
                            {
                                '_id': ObjectId(loginID)
                            }
                    }
            }
        )
        return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, g.userKeyPEM)), 200


@api.route('/LoginData', methods=['POST'])
def postLoginData():
    js = request.json
    js = auxiliaryFuncs.decryptAES(js, current_app.config['SERVER_DECRYPTOR'])

    if 'passwordStrength' not in js:
        js['passwordStrength'] = auxiliaryFuncs.measurePasswordStrength(js['password'])

    logindat = {
        "_id": ObjectId(),
        'site': js['site'],
        'login': g.client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random", g.data_key_id),
        'password': g.client_encryption.encrypt(js['password'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random", g.data_key_id),
        'passwordStrength': js['passwordStrength'],
        'note': js['note']
    }

    g.db.passwordManager.accounts.find_one_and_update(
        {
            '_id': ObjectId(g.userID)
        },
        {
            '$push':
                {
                    'logindata': logindat
                }
        }
    )

    return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, g.userKeyPEM)), 201


@api.route('/AllSites', methods=['GET'])
def getAllSites():
    response = g.db.passwordManager.accounts.find_one(
        {
            '_id': ObjectId(g.userID)
        },
        {
            'logindata.password': 0,
            'login': 0,
            'password': 0,
            'email': 0
        }
    )
    resp = response['logindata']
    return json_util.dumps(auxiliaryFuncs.encryptAES(resp, g.userKeyPEM)), 200


@api.route('/Backup', methods=['GET'])
def getBackup():
    response = g.db.passwordManager.accounts.find_one(
        {
            '_id': ObjectId(g.userID)
        },
        {
            'logindata': 1
        }
    )
    return json_util.dumps(auxiliaryFuncs.encryptAES(response['logindata'], g.userKeyPEM)), 200
