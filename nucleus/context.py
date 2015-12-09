# -*- coding: utf-8 -*-
"""
    nucleus.context
    ~~~~~

    Context and container models

    :copyright: (c) 2015 by Vincent Ahrend.
"""

from flask import url_for
from flask.ext.login import current_user

import identity

from uuid import uuid4
from sqlalchemy import Column, Integer, String, DateTime, \
    ForeignKey
from sqlalchemy.orm import relationship, backref

from . import logger
from .base import Model, BaseModel


class Mindset(Model):
    """
    Mindsets are collections of objects with associated layout information.

    Atributes:
        id: 32 byte ID generated by uuid4().hex
        modified: Datetime of last recorded modification
        author: Persona that created this Mindset
        kind: For what kind of context is this Mindset used
        index: Query for Thoughts that are contained in this Mindset
    """
    __tablename__ = 'mindset'

    __mapper_args__ = {
        'polymorphic_identity': 'mindset',
        'polymorphic_on': 'kind'
    }

    id = Column(String(32), primary_key=True)
    modified = Column(DateTime())
    kind = Column(String(16))
    state = Column(Integer(), default=0)

    author_id = Column(
        String(32),
        ForeignKey('identity.id', use_alter=True, name="fk_author_id"))
    author = relationship('Identity',
        backref=backref('mindsets'),
        primaryjoin="Identity.id==Mindset.author_id",
        post_update=True)

    def __contains__(self, key):
        """Return True if the given key is contained in this Mindset.

        Args:
            key: db.model.key to look for
        """
        return (key in self.index)

    def __len__(self):
        return self.index.count()

    def __repr__(self):
        return "<{} [{}]>".format(self.name, self.id[:6])

    def authorize(self, action, author_id=None):
        """Return True if this Mindset authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.ACCESS_MODES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        if BaseModel.authorize(self, action, author_id=author_id):
            if self.kind == "blog" and isinstance(self.author, identity.Persona):
                return self.author.id == author_id
            elif self.kind == "blog" and isinstance(self.author, identity.Movement):
                # Everyone can update
                if action == "update":
                    return True
                # Only author can insert and delete
                elif self.author_id == author_id:
                    return True

            elif self.kind == "index":
                p = identity.Persona.query.filter(identity.Persona.index_id == self.id)
                return p.id == author_id
        return False

    def get_absolute_url(self):
        """Return URL for this Mindset depending on kind"""
        raise NotImplementedError("Base Mindset doesn't have its own URL scheme")

    @property
    def name(self):
        """Return an identifier for this Mindset that can be used in UI

        Returns:
            string: Name for this Mindset
        """
        rv = "Mindset by {}".format(self.author.username)
        return rv


class Mindspace(Mindset):
    """Model internal thoughts of an Identity"""

    __mapper_args__ = {
        'polymorphic_identity': 'mindspace'
    }

    def authorize(self, action, author_id=None):
        if isinstance(self.author, identity.Persona):
            rv = (author_id == self.author.id)
        elif isinstance(self.author, identity.Movement):
            rv = self.author.authorize(action, author_id)
        return rv

    def get_absolute_url(self):
        """Return URL for this Mindset depending on kind"""
        rv = None

        if isinstance(self.author, identity.Movement):
            m = identity.Movement.query.filter(identity.Movement.mindspace_id == self.id).first()
            rv = url_for("web.movement_mindspace", id=m.id)

        elif isinstance(self.author, identity.Persona):
            if self.author == current_user.active_persona:
                rv = url_for("web.persona", id=self.author_id)

        else:
            raise NotImplementedError("Mindspace with unknown author kind has no URL")

        return rv

    @property
    def name(self):
        """Return an identifier for this Mindset that can be used in UI

        Returns:
            string: Name for this Mindset
        """
        return "{} mindspace".format(self.author.username)


class Blog(Mindset):
    """Model external communication of an identity"""

    __mapper_args__ = {
        'polymorphic_identity': 'blog'
    }

    def authorize(self, action, author_id=None):
        if action == "read":
            rv = True
        else:
            if isinstance(self.author, identity.Movement):
                rv = (author_id == self.author.id) \
                    or (author_id == self.author.admin.id)
            else:
                rv = (author_id == self.author.id)
        return rv

    def get_absolute_url(self):
        """Return URL for this Mindset depending on kind"""
        rv = None

        if isinstance(self.author, identity.Movement):
            m = identity.Movement.query.filter(identity.Movement.blog_id == self.id).first()
            rv = url_for("web.movement_blog", id=m.id)

        elif isinstance(self.author, identity.Persona):
            p = identity.Persona.query.filter(identity.Persona.blog_id == self.id).first()
            rv = url_for("web.persona_blog", id=p.id)

        else:
            raise NotImplementedError("Blog with unknown author kind has no URL")

        return rv

    @property
    def name(self):
        """Return an identifier for this Mindset that can be used in UI

        Returns:
            string: Name for this Mindset
        """
        return "{} blog".format(self.author.username)


class Dialogue(Mindset):
    """Model a private conversation between two parties"""

    __mapper_args__ = {
        'polymorphic_identity': 'dialogue'
    }

    other = relationship("Identity",
        primaryjoin="identity.c.id==mindset.c.other_id")
    other_id = Column(String(32), ForeignKey(
        'identity.id', use_alter=True, name="fk_dialogue_other"))

    def authorize(self, action, author_id=None):
        return (author_id == self.author.id) or (author_id == self.other_id)

    def get_absolute_url(self):
        """Return URL for this Mindset depending on kind"""
        rv = None

        if current_user.is_anonymous():
            rv = None
        else:
            if current_user.active_persona == self.author:
                rv = url_for("web.persona", id=self.other_id)
            elif current_user.active_persona == self.other:
                rv = url_for("web.persona", id=self.author_id)

        return rv

    @classmethod
    def get_chat(cls, author, other):
        """Get or create a dialogue between the two given Personas

        Return value may be a new instance. Check for that using

        >> from sqlalchemy import inspect
        >> inspect(rv).transient == True

        Args:
            author (Identity): One party to the conversation
            other (Identity): Other party to the conversation

        Returns:
            Dialogue: Existing or new dialogue between the two parties
        """
        rv = cls.query.filter_by(author=author).filter_by(other=other).first()
        if rv is None:
            rv = cls.query.filter_by(author=other).filter_by(other=author).first()
        if rv is None:
            logger.info("Creating new dialogue between {} and {}".format(
                author, other))
            rv = cls(id=uuid4().hex, author=author, other=other)

        return rv

    @property
    def name(self):
        """Return an identifier for this Mindset that can be used in UI

        Returns:
            string: Name for this Mindset
        """
        if current_user and not current_user.is_anonymous():
            if current_user.active_persona == self.author:
                rv = "Dialogue with {}".format(self.other.username)
            elif current_user.active_persona == self.other:
                rv = "Dialogue with {}".format(self.author.username)
        else:
            rv = "Private Dialogue"

        return rv
