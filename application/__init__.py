from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy

application = Flask(__name__)
application.config.from_object('config')
db = SQLAlchemy(application)

from application import views, models



if not application.debug:
    import os
    import logging

    from logging import Formatter, FileHandler
    from config import basedir

    file_handler = FileHandler(os.path.join(basedir,'error.log'))
    file_handler.setFormatter(Formatter('%(asctime)s %(levelname)s: %(message)s '
'[in %(pathname)s:%(lineno)d]'))
    application.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    application.logger.addHandler(file_handler)
    application.logger.info('errors')
