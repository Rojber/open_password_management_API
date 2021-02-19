from flask import g
from bson import json_util, ObjectId
from app.api import api
from app import auxiliaryFuncs


@api.route('/Backup', methods=['GET'])
def getBackup():
    response = g.db.passwordManager.accounts.find_one(
        {
            '_id': ObjectId(g.userID)
        },
        {
            '_id': 0,
            'logindata': 1
        }
    )
    return json_util.dumps(auxiliaryFuncs.encryptAES(response['logindata'], g.userKeyPEM)), 200