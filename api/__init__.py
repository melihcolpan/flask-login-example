from api.models.user_model import db
from api.routes.routes import limiter
from api.routes.routes import route_page
from api.utils.const import SQLALCHEMY_DATABASE_URI
from flask import Flask

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.register_blueprint(route_page)

db.init_app(app)
db.app = app
db.create_all()

limiter.init_app(app)
