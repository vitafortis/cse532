import os
from flask_appbuilder.security.manager import AUTH_DB

basedir = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = "f0708600cdcbf030e054e244a4ce28a2bc54447b1f7be3e75d479753afb7ba6a"
SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "app.db")
CSRF_ENABLED = True

AUTH_TYPE = AUTH_DB

BABEL_DEFAULT_LOCALE = "en"
BABEL_DEFAULT_FOLDER = "translations"
LANGUAGES = {
    "en": {"flag": "gb", "name": "English"},
    "es": {"flag": "es", "name": "Spanish"},
}
UPLOAD_FOLDER = os.path.join(basedir, "app/static/uploads/")
IMG_UPLOAD_FOLDER = UPLOAD_FOLDER
IMG_UPLOAD_URL = "/static/uploads/"
