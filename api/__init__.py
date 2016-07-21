from api.utils.database import db
from api.routes.routes import limiter
from api.routes.routes import route_page
from flask import Flask
from api.utils.config import DevelopmentConfig, ProductionConfig

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)
app.register_blueprint(route_page)

db.init_app(app)
db.app = app
db.create_all()

limiter.init_app(app)
