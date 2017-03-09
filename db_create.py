from config import SQLALCHEMY_DATABASE_URI
from application import db
#db.drop_all()
db.create_all()
