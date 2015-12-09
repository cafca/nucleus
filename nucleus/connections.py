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

config = Config(os.path.join(os.getcwd(), "glia"))
config.from_envvar("GLIA_CONFIG")


class SQLAlchemy(SQLAlchemyBase):
    """SQLAlchemy extension that integrates custom declarative bases."""
    def __init__(self,
                 app=None,
                 use_native_unicode=True,
                 session_options=None,
                 model_class=None):
        self.Model = model_class

        super(SQLAlchemy, self).__init__(app,
                                         use_native_unicode,
                                         session_options)

    def make_declarative_base(self, metadata=None):
        """Creates or extends the declarative base."""
        if self.Model is None:
            self.Model = super(SQLAlchemy, self).make_declarative_base(metadata=metadata)
        else:
            set_query_property(self.Model, self.session)
        return self.Model

cache = Cache()
db = SQLAlchemy(model_class=Model)
