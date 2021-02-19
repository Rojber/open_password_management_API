from flask import g
from bson import json_util, ObjectId
from app.api import api
from app import auxiliaryFuncs


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
