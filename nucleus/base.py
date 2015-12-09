# -*- coding: utf-8 -*-
"""
    nucleus.models.base
    ~~~~~

    Base model for Glia

    :copyright: (c) 2015 by Vincent Ahrend.
"""
from sqlalchemy.ext.declarative import declarative_base

from . import CHANGE_TYPES


class BaseModel(object):
    """ Base model for rktik"""
    def authorize(self, action, author_id=None):
        """Return True if this object authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        if action not in CHANGE_TYPES:
            return False
        return True

Base = declarative_base(cls=BaseModel)
