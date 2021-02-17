from bson.binary import STANDARD, UUID, Binary
from pymongo import MongoClient
from bson import CodecOptions
from pymongo.encryption_options import AutoEncryptionOpts
from pymongo.encryption import ClientEncryption
import base64


# you need 96 bytes long cryptographically secure master key as a part of your CSFLE data key
def read_master_key(path="master-key.txt"):
    with open(path, "rb") as f:
        return f.read(96)


def create_csfle_client(connection_string):
    local_master_key = read_master_key()
    kms_providers = {
        "local": {
            "key": local_master_key,
        },
    }

    csfle_helper = CsfleHelper(kms_providers=kms_providers, key_alt_name="main_key", connection_string=connection_string)
    data_key_id, base64_data_key = csfle_helper.find_or_create_data_key()
    data_key_id = Binary(base64.b64decode(base64_data_key), 4)
    schema = csfle_helper.create_json_schema(data_key=base64_data_key)
    mongoClient = csfle_helper.get_csfle_enabled_client(schema)
    client_encryption = csfle_helper.client_encryption
    return mongoClient, client_encryption, data_key_id


def drop_database(connection_string):
    local_master_key = read_master_key()
    kms_providers = {
        "local": {
            "key": local_master_key,
        },
    }

    csfle_helper = CsfleHelper(kms_providers=kms_providers, key_alt_name="main_key", connection_string=connection_string)
    data_key_id, base64_data_key = csfle_helper.find_or_create_data_key()
    data_key_id = Binary(base64.b64decode(base64_data_key), 4)
    schema = csfle_helper.create_json_schema(data_key=base64_data_key)
    mongoClient = csfle_helper.get_csfle_enabled_client(schema)
    db = mongoClient.passwordManager
    mongoClient.drop_database(db)


class CsfleHelper:
    def __init__(self,
                 kms_providers=None,
                 key_db="encryption",
                 key_coll="__keyVault",
                 key_alt_name=None,
                 schema=None,
                 connection_string=None,
                 mongocryptd_bypass_spawn=False,
                 mongocryptd_spawn_path="mongocryptd"):
        super().__init__()
        if kms_providers is None:
            raise ValueError("kms_provider is required")
        self.kms_providers = kms_providers
        self.key_alt_name = key_alt_name
        self.key_db = key_db
        self.key_coll = key_coll
        self.key_vault_namespace = f"{self.key_db}.{self.key_coll}"
        self.schema = schema
        self.client_encryption = None
        self.connection_string = connection_string
        self.mongocryptd_bypass_spawn = mongocryptd_bypass_spawn
        self.mongocryptd_spawn_path = mongocryptd_spawn_path

    def ensure_unique_index_on_key_vault(self, key_vault):
        key_vault.create_index("keyAltNames",
                               unique=True,
                               partialFilterExpression={
                                   "keyAltNames": {
                                       "$exists": True
                                   }
                               })

    def find_or_create_data_key(self):

        key_vault_client = MongoClient(self.connection_string)

        key_vault = key_vault_client[self.key_db][self.key_coll]

        self.ensure_unique_index_on_key_vault(key_vault)

        data_key = key_vault.find_one(
            {"keyAltNames": self.key_alt_name}
        )

        self.client_encryption = ClientEncryption(self.kms_providers,
                                                  self.key_vault_namespace,
                                                  key_vault_client,
                                                  CodecOptions(uuid_representation=STANDARD)
                                                  )

        if data_key is None:
            data_key = self.client_encryption.create_data_key(
                "local", key_alt_names=[self.key_alt_name])
            uuid_data_key_id = UUID(bytes=data_key)

        else:
            uuid_data_key_id = data_key["_id"]

        base_64_data_key_id = (base64
                               .b64encode(uuid_data_key_id.bytes)
                               .decode("utf-8"))

        return uuid_data_key_id, base_64_data_key_id

    def get_regular_client(self):
        return MongoClient(self.connection_string)

    def get_csfle_enabled_client(self, schema):
        return MongoClient(
            self.connection_string,
            auto_encryption_opts=AutoEncryptionOpts(
                self.kms_providers,
                self.key_vault_namespace,
                mongocryptd_bypass_spawn=self.mongocryptd_bypass_spawn,
                mongocryptd_spawn_path=self.mongocryptd_spawn_path,
                bypass_auto_encryption=True,
                schema_map=schema),
            connect=False
        )

    @staticmethod
    def create_json_schema(data_key):
        return {
            'bsonType': 'object',
            'encryptMetadata': {
                'keyId': [Binary(base64.b64decode(data_key), 4)]
            },
            'properties': {
                'email': {
                    'encrypt': {
                        'bsonType': "string",
                        'algorithm': "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                    }
                },
                'password': {
                    'encrypt': {
                        'bsonType': "string",
                        'algorithm': "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                    }
                },
                'login': {
                    'encrypt': {
                        'bsonType': "string",
                        'algorithm': "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                    }
                },
                'logindata': {
                    'bsonType': "object",
                    'properties': {
                        'password': {
                            'encrypt': {
                                'bsonType': "string",
                                'algorithm': "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                            }
                        },
                        'login': {
                            'encrypt': {
                                'bsonType': "string",
                                'algorithm': "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                            }
                        }
                    }
                }
            }
        }
