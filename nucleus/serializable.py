# -*- coding: utf-8 -*-
"""
    nucleus.serializable
    ~~~~~

    JSON serialization

    :copyright: (c) 2015 by Vincent Ahrend.
"""
import json

from . import CHANGE_TYPES


class Serializable():
    """ The serializable model captures all functionality needed for JSON
        serialization and encryption in the future P2P extension. All models
        inheriting from Serializable share these attributes:

    Attributes:
        _insert_required (list): A list of the fields that are required for
            creating a new instance of a given model
        _update_required (list): A list of the fields that are required for
            updating an instance of a given model
        id (String): A unique identifier
        modified (Datetime): Last modification timestamp
    """
    _insert_required = ["id", "modified"]
    _update_required = ["id", "modified"]

    id = None
    modified = None

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

    @staticmethod
    def create_from_changeset(changeset,
            stub=None, update_sender=None, update_recipient=None):
        """Return a new instance of this model given a dictionary containing
            the required values as specified in *_insert_required*. A stub may
            be passed whose properties will be overwritten. Passing Persona
            objects for the update_sender and update_recipient parameters will
            request any linked missing objects with a request to/from these
            Personas respectively.

        Args:
            changeset (dict): Dictionary of model values. Requires all keys
                defined in cls._insert_required with class-specific values.
            stub (Serializable): (Optional) model instance whose values will be
                overwritten with those defined in changeset.
            update_sender (Persona): (Optional) author of this changeset. Will be
                used as recipient of subsequent object requests.
            update_recipient (Persona): (Optional) recipient of this changeset.
                Will be used as sender of subsequent object requests.

        Returns:
            Serializable: Instance created from changeset

        Raises:
            KeyError: Missing key in changeset
            TypeError: Argument has wrong type
            ValueError: Argument value cannot be processed
        """
        raise NotImplementedError()

    def export(self, exclude=[], include=None, update=False):
        """Return a dictionary representation of this object containing all
            fields specified in _insert_required. Optional parameters exclude
            and include for manually specifying field names to be exported and
            update parameter for exporting fields defined in _update_required.

        Args:
            update (Bool): Export only attributes defined in
                `self._update_required`

        Returns:
            Dict: The serialized object

        Raises:
            KeyError: If a key was not found
        """
        attr_names = self._update_required if update is True else self._insert_required

        if include:
            attr_names = include
        else:
            attr_names = [a for a in attr_names if a not in exclude]

        return {attr: str(getattr(self, attr)) for attr in attr_names}

    def json(self, update=False):
        """Return this object JSON encoded.

        Args:
            update (Boolean): (optiona) See export docstring

        Returns:
            Str: JSON-encoded serialized instance
        """
        return json.dumps(self.export(update=update), indent=4)

    def update_from_changeset(self, changeset,
            update_sender=None, update_recipient=None):
        """Similar to create_from_changeset but not a static but an instance
            method. Stub parameter not supported.

        Args:
            changeset (dict): Dictionary of model values. Requires all keys
                defined in self._update_required with class-specific values.
            update_sender (Persona): (Optional) author of this changeset. Will
                be used as recipient of subsequent object requests.
            update_recipient (Persona): (Optional) recipient of this changeset.
                Will be used as sender of subsequent object requests.

        Returns:
            Serializable: Updated instance

        Raises:
            KeyError: Missing key in changeset
            TypeError: Argument has wrong type
            ValueError: Argument value cannot be processed
        """
        raise NotImplementedError()

    @classmethod
    def validate_changeset(cls, changeset, update=False):
        """Return missing keys from this class’ _insert_required given a
            changeset.

        Args:
            changeset(dict): See created_from_changeset, update_from_changeset
            update(Bool): If True use cls._update_required instead of
                cls._insert_required

        Returns:
            List: Missing keys
        """
        required_keys = cls._update_required if update else cls._insert_required
        missing = list()

        for k in required_keys:
            if k not in changeset.keys():
                missing.append(k)
        return missing
