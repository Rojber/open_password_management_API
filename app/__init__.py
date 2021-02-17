from flask import Flask
#from flask.ext.mail import Mail
from config import config

#mail = Mail()


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    #mail.init_app(app)

    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/api')

    from .public import public as public_blueprint
    app.register_blueprint(public_blueprint, url_prefix='/api')

    return app

# TODO errors grinberg str 181, 188
