# -*- coding: utf-8 -*-
"""
    connections.py
    ~~~~~

    Setup connections to DBAPI and other external services

    :copyright: (c) 2013 by Vincent Ahrend.
"""

import os
from flask.config import Config
from flask.ext.sqlalchemy import SQLAlchemy as SQLAlchemyBase
from flask.ext.cache import Cache

from .base import set_query_property, Model


class SQLAlchemy(SQLAlchemyBase):
    """Flask extension that integrates alchy with Flask-SQLAlchemy."""
    def __init__(self,
                 app=None,
                 use_native_unicode=True,
                 session_options=None,
                 model_class=None):
        self.model_class = model_class

        super(SQLAlchemy, self).__init__(app,
                                         use_native_unicode,
                                         session_options)

    def make_declarative_base(self):
        """Creates or extends the declarative base."""
        if self.model_class is None:
            self.model_class = super(SQLAlchemyBase, self).make_declarative_base()
        else:
            set_query_property(self.model_class, self.session)
        return self.model_class

config = Config(os.path.join([os.getcwd(), "glia"]))
config.from_envvar("GLIA_CONFIG")

cache = Cache()

db = SQLAlchemy(model_class=Model)
