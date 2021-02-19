from flask import Flask
from config import config


def create_app(config_name):
    app = Flask(__name__)

    if config_name not in config:
        return

    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/api')

    from .public import public as public_blueprint
    app.register_blueprint(public_blueprint, url_prefix='/api')

    return app

# TODO errors grinberg str 181, 188
