import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_appbuilder import AppBuilder

logging.basicConfig(format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")
logging.getLogger().setLevel(logging.DEBUG)

app = Flask(__name__)
app.config.from_object("config")
db = SQLAlchemy(app)

with app.app_context():
    # import models so SQLAlchemy sees them
    from . import models
    db.create_all()

    appbuilder = AppBuilder(app, db.session)
    from . import views
from .vuln_api import vuln_api
app.register_blueprint(vuln_api)
