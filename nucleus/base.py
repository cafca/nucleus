# -*- coding: utf-8 -*-
"""
    nucleus.base
    ~~~~~

    Base model for Glia

    :copyright: (c) 2015 by Vincent Ahrend.
"""
from math import ceil
from sqlalchemy import orm
from sqlalchemy.ext.declarative import declarative_base

from . import ACCESS_MODES


class BaseQuery(orm.Query):
    """The default query object used for models. This can be
    subclassed and replaced for individual models by setting
    the Model.query_class attribute. This is a subclass of a
    standard SQLAlchemy sqlalchemy.orm.query.Query class and
    has all the methods of a standard query as well.
    """
    pass


class BaseModel(object):
    """ Base model for rktik"""

    #: the query class used. The `query` attribute is an instance
    #: of this class. By default a `BaseQuery` is used.
    query_class = BaseQuery

    #: an instance of `query_class`. Can be used to query the
    #: database for instances of this model.
    query = None

    def authorize(self, action, author_id=None):
        """Return True if this object authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.ACCESS_MODES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        if action not in ACCESS_MODES:
            return False
        return True


class QueryProperty(object):
    """Query property accessor which gives a model access to query capabilities
    via `ModelBase.query` which is equivalent to ``session.query(Model)``.
    """
    def __init__(self, session):
        self.session = session

    def __get__(self, model, Model):
        mapper = orm.class_mapper(Model)

        if mapper:
            if not getattr(Model, 'query_class', None):
                Model.query_class = BaseQuery

            query_property = Model.query_class(mapper, session=self.session())

            return query_property


def set_query_property(model_class, session):
    model_class.query = QueryProperty(session)

Model = declarative_base(cls=BaseModel)
