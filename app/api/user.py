from flask import request, current_app, g
from bson import json_util, ObjectId
from app.api import api
from app import auxiliaryFuncs


@api.route('/User', methods=['GET', 'PUT', 'DELETE'])
def manageAccount():
    if request.method == 'GET':
        response = g.db.passwordManager.accounts.find_one(
            {
                '_id': ObjectId(g.userID)
            },
            {
                'login': 1,
                'email': 1
            }
        )
        return json_util.dumps(auxiliaryFuncs.encryptAES(response, g.userKeyPEM)), 200
    if request.method == 'PUT':
        js = request.json
        js = auxiliaryFuncs.decryptAES(js, current_app.config['SERVER_DECRYPTOR'])
        g.db.passwordManager.accounts.find_one_and_update(
            {
                '_id': ObjectId(g.userID)
            },
            {
                '$set':
                    {
                        'email': g.client_encryption.encrypt(js['email'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                           g.data_key_id),
                        'login': g.client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                           g.data_key_id),
                        'password': g.client_encryption.encrypt(js['password'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random",
                                                              g.data_key_id)
                    }
            }
        )
        return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, g.userKeyPEM)), 201
    if request.method == 'DELETE':
        g.db.passwordManager.accounts.delete_one(
            {
                '_id': ObjectId(g.userID)
            }
        )
        return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, g.userKeyPEM)), 200
