import os
import app.auxiliaryFuncs

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    #SECRET_KEY = os.environ.get('SECRET_KEY')
    #SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    MAIL_SUBJECT_PREFIX = '[Flasky]'
    MAIL_SENDER = 'Flasky Admin <flasky@example.com>'
    ADMIN = os.getenv('ADMIN')
    __public_server_key, __private_server_key = app.auxiliaryFuncs.getRSAKeys()
    EXPORT_PUBLIC_SERVER_KEY = app.auxiliaryFuncs.exportKey(__public_server_key)
    SERVER_DECRYPTOR = app.auxiliaryFuncs.getDecryptor(__private_server_key)
    SERVER_ENCRYPTOR = app.auxiliaryFuncs.getEncryptor(__public_server_key)

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    # enter here your connection string to MongoDB development database (works with MongoDB Atlas too)
    MONGODB_CONNECTION_STRING = os.getenv('DEV_MONGODB_CONNECTION_STRING')


class TestingConfig(Config):
    TESTING = True
    # enter here your connection string to MongoDB test database (works with MongoDB Atlas too)
    MONGODB_CONNECTION_STRING = os.getenv('TEST_MONGODB_CONNECTION_STRING')


class ProductionConfig(Config):
    # enter here your connection string to MongoDB production database (works with MongoDB Atlas too)
    MONGODB_CONNECTION_STRING = os.getenv('MONGODB_CONNECTION_STRING')


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
