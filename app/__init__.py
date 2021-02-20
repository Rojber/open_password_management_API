from flask import Flask
from config import config
from flask_swagger_ui import get_swaggerui_blueprint


def create_app(config_name):
    app = Flask(__name__)

    if config_name not in config:
        return

    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    # initiate swagger
    swagger_url = '/api/Docs'
    api_url = '/static/swagger.json'
    swagger_ui_blueprint = get_swaggerui_blueprint(
        swagger_url,
        api_url,
        config={
            'app_name': "Open Password Management API",
            'persistAuthorization': False
        }
    )
    app.register_blueprint(swagger_ui_blueprint, url_prefix=swagger_url)

    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/api')

    from .public import public as public_blueprint
    app.register_blueprint(public_blueprint, url_prefix='/api')

    return app
