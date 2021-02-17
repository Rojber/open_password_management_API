from flask import current_app, g
from bson import json_util
from app.public import public
from app.mongoCli import create_csfle_client, drop_database
from tests import populate_database


@public.before_request
def before_request():
    g.db, g.client_encryption, g.data_key_id = create_csfle_client(current_app.config['MONGODB_CONNECTION_STRING'])


@public.teardown_request
def after_request(response):
    g.db.close()
    return response


@public.route('/GetPublicKey', methods=['GET'])
def getKey():
    return current_app.config['EXPORT_PUBLIC_SERVER_KEY'], 200


# DEBUG METHODS - DISABLE BEFORE RELEASE!
@public.route('/Populate', methods=['GET'])
def pop():
    populate_database.populate(g.db, g.client_encryption, g.data_key_id)
    return 'Database Populated with 20 accounts!', 200


@public.route('/AllData', methods=['GET'])
def allData():
    response = g.db.passwordManager.accounts.find()
    return json_util.dumps(response), 200


@public.route('/DropDb', methods=['GET'])
def dropDb():
    drop_database(current_app.config['MONGODB_CONNECTION_STRING'])
    return 'Database cleared!', 200
