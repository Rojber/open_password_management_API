from secrets import choice
from flask import request, current_app, g
from bson import json_util
from app.api import api
from app import auxiliaryFuncs
import string


@api.route('/api/PasswordStrength', methods=['POST'])
def getPasswordStrength():
    js = request.json
    js = auxiliaryFuncs.decryptAES(js, current_app.config['SERVER_DECRYPTOR'])

    password = js['password']
    resp = {
        'passwordStrength': auxiliaryFuncs.measurePasswordStrength(password)
    }
    return json_util.dumps(auxiliaryFuncs.encryptAES({'response': resp}, g.userKeyPEM)), 200


@api.route('/api/StrongPassword/<PasswordLen>', methods=['GET'])
def getStrongPassword(PasswordLen):
    chars = string.ascii_letters + string.digits + "!#$%&()*+,-./<=>?@[]^_{|}~"
    passw = ''.join(choice(chars) for i in range(int(PasswordLen)))
    return json_util.dumps(auxiliaryFuncs.encryptAES({'response': str(passw)}, g.userKeyPEM)), 200


@api.route('/api/PasswordStrength/Hibp', methods=['POST'])
def passwordCheckHIBP():
    js = request.json
    js = auxiliaryFuncs.decryptAES(js, current_app.config['SERVER_DECRYPTOR'])

    password = js['password']
    if auxiliaryFuncs.hibpIsPwned(password) is True:
        return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'PASSWORD LEAKED'}, g.userKeyPEM)), 200
    else:
        return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, g.userKeyPEM)), 200
