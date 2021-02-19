from random import randint
from bson.objectid import ObjectId


def populate(db, client_encryption, data_key_id):
    account1 = {
        'email': client_encryption.encrypt("test1@test.com", "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
        'login': client_encryption.encrypt("test1", "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
        'password': client_encryption.encrypt("test1", "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
        'logindata': [
            {
                "_id": ObjectId(),
                'site': "test_login_site1.com",
                'login': client_encryption.encrypt("test_login1", "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
                'password': client_encryption.encrypt("test_password1", "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
                'passwordStrength': randint(1, 5),
                'note': "note1"
            },
            {
                "_id": ObjectId(),
                'site': "test_login_site2.com",
                'login': client_encryption.encrypt("test_login2", "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
                'password': client_encryption.encrypt("test_password2", "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
                'passwordStrength': randint(1, 5),
                'note': "note2"
            }
        ]
    }

    account2 = {
        'email': client_encryption.encrypt("test2@test.com", "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
        'login': client_encryption.encrypt("test2", "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
        'password': client_encryption.encrypt("test2", "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
        'logindata': [
            {
                "_id": ObjectId(),
                'site': "test_login_site1.com",
                'login': client_encryption.encrypt("test_login1", "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
                'password': client_encryption.encrypt("test_password1", "AEAD_AES_256_CBC_HMAC_SHA_512-Random",
                                                      data_key_id),
                'passwordStrength': randint(1, 5),
                'note': "note1"
            },
            {
                "_id": ObjectId(),
                'site': "test_login_site2.com",
                'login': client_encryption.encrypt("test_login2", "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
                'password': client_encryption.encrypt("test_password2", "AEAD_AES_256_CBC_HMAC_SHA_512-Random",
                                                      data_key_id),
                'passwordStrength': randint(1, 5),
                'note': "note2"
            }
        ]
    }

    # Insert users directly into MongoDB
    db.passwordManager.accounts.insert_one(account1)
    db.passwordManager.accounts.insert_one(account2)

    print('Finished creating testing database')
