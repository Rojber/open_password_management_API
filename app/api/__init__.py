from flask import Blueprint


api = Blueprint('api', __name__)

from . import login_data, user, password