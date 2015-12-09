# -*- coding: utf-8 -*-
"""
    connections.py
    ~~~~~

    Setup connections to DBAPI and other external services

    :copyright: (c) 2013 by Vincent Ahrend.
"""

import os
from flask.config import Config
# from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.cache import Cache
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

config = Config(os.pathsep.join([os.getcwd(), "glia"]))
config.from_envvar("GLIA_CONFIG")

# db = SQLAlchemy()
cache = Cache()

engine = create_engine(config.get("SQLALCHEMY_DATABASE_URI"))

Session = sessionmaker(bind=engine)
# session = Session()
