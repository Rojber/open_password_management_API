from flask import request, g
from bson import json_util, ObjectId
from app.api import api
from app import auxiliaryFuncs


@api.route('/LogOut', methods=['GET'])
def log_out():
    if request.method == 'GET':
        g.db.passwordManager.sessions.delete_one(
            {
                '_id': ObjectId(g.userID)
            }
        )
        return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, g.userKeyPEM)), 200
