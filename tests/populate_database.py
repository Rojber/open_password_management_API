from random import randint
from bson.objectid import ObjectId
from faker import Faker
from faker.providers import internet, person, company, address, phone_number, date_time

fake = Faker()
fake.add_provider(internet)
fake.add_provider(person)
fake.add_provider(company)
fake.add_provider(address)
fake.add_provider(phone_number)
fake.add_provider(date_time)


def populate(db, client_encryption, data_key_id):
    for x in range(1, 20):
        account = {
            'email': client_encryption.encrypt(fake.ascii_company_email(), "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
            'login': client_encryption.encrypt(fake.user_name(), "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
            'password': client_encryption.encrypt(fake.user_name(), "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
            'logindata': [
                {
                    "_id": ObjectId(),
                    'site': fake.domain_name(),
                    'login': client_encryption.encrypt(fake.user_name(), "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
                    'password': client_encryption.encrypt(fake.user_name(), "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
                    'passwordStrength': randint(1, 5),
                    'note': fake.domain_word()
                },
                {
                    "_id": ObjectId(),
                    'site': fake.domain_name(),
                    'login': client_encryption.encrypt(fake.user_name(), "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
                    'password': client_encryption.encrypt(fake.user_name(), "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
                    'passwordStrength': randint(1, 5),
                    'note': fake.domain_word()
                }
            ]
        }
        # Insert users directly into MongoDB
        result = db.accounts.insert_one(account)

        # Print to the console the ObjectID of the new document
        print('Created {0} of 20 as {1}'.format(x, result.inserted_id))

    print('Finished creating 20 accounts')

