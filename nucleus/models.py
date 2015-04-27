import datetime
import json
import iso8601
import semantic_version

from base64 import b64encode, b64decode
from flask import url_for, current_app, session
from flask.ext.login import current_user, UserMixin
from hashlib import sha256
from keyczar.keys import RsaPrivateKey, RsaPublicKey
from uuid import uuid4

from . import ONEUP_STATES, STAR_STATES, PLANET_STATES, \
    PersonaNotFoundError, UnauthorizedError, notification_signals, \
    CHANGE_TYPES, logger, planet_sort_rank
from .helpers import epoch_seconds

from glia.database import db

request_objects = notification_signals.signal('request-objects')


class Serializable():
    """ Make SQLAlchemy models json serializable

    Attributes:
        _insert_required: Default attributes to include in export
        _update_required: Default attributes to include in export with update=True
    """
    id = None
    modified = None

    _insert_required = ["id", "modified"]
    _update_required = ["id", "modified"]

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

    def export(self, exclude=[], include=None, update=False):
        """Return this object as a dict.

        Args:
            update (Bool): Export only attributes defined in `self._update_required`

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

    @classmethod
    def validate_changeset(cls, changeset, update=False):
        """Check whether changeset contains all keys defined as required for this class.

        Args:
            changeset(dict): See created_from_changeset, update_from_changeset
            update(Bool): If True use cls._update_required instead of cls._insert_required

        Returns:
            List: Missing keys
        """
        required_keys = cls._update_required if update else cls._insert_required
        missing = list()

        for k in required_keys:
            if k not in changeset.keys():
                missing.append(k)
        return missing

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new instance from a changeset.

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

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update self with new values in changeset

        Args:
            changeset (dict): Dictionary of model values. Requires all keys
                defined in self._update_required with class-specific values.
            update_sender (Persona): (Optional) author of this changeset. Will be
                used as recipient of subsequent object requests.
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


class PersonaAssociation(db.Model):
    """Connects user accounts and personas"""
    __tablename__ = "persona_association"
    left_id = db.Column(db.String(32), db.ForeignKey('user.id'), primary_key=True)
    right_id = db.Column(db.String(32), db.ForeignKey('persona.id'), primary_key=True)
    active = db.Column(db.Boolean(), default=False)
    persona = db.relationship("Persona", backref="associations")


class User(UserMixin, db.Model):
    """A user of the website"""

    __tablename__ = 'user'
    id = db.Column(db.String(32), primary_key=True, default=uuid4().hex)
    email = db.Column(db.String(128))
    created = db.Column(db.DateTime)
    modified = db.Column(db.DateTime)
    pw_hash = db.Column(db.String(64))
    active = db.Column(db.Boolean(), default=False)
    authenticated = db.Column(db.Boolean(), default=True)
    associations = db.relationship('PersonaAssociation', lazy="dynamic", backref="user")
    signup_code = db.Column(db.String(128))

    def __repr__(self):
        return "<User {}>".format(self.email)

    def check_password(self, password):
        """Return True if password matches user password

        Args:
            password (String): Password entered by user in login form
        """
        pw_hash = sha256(password).hexdigest()
        return self.pw_hash == pw_hash

    def set_password(self, password):
        """Set password to a new value

        Args:
            password (String): Plaintext value of the new password
        """
        pw_hash = sha256(password).hexdigest()
        self.pw_hash = pw_hash

    def get_id(self):
        return self.id

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return self.active

    def is_anonymous(self):
        return False

    def valid_signup_code(self, signup_code):
        """Return True if the given signup code is valid, and less than 7 days
        have passed since signup.

        Args:
            signup_code (String): 128byte string passed in registration email
        """
        if signup_code != self.signup_code:
            return False

        if (datetime.datetime.utcnow() - self.created) > datetime.timedelta(days=7):
            return False

        return True

    @property
    def active_persona(self):
        try:
            return self.associations.filter_by(active=True).first().persona
        except AttributeError:
            # no persona associated
            return None


t_identity_vesicles = db.Table(
    'identity_vesicles',
    db.Column('identity_id', db.String(32), db.ForeignKey('identity.id')),
    db.Column('vesicle_id', db.String(32), db.ForeignKey('vesicle.id'))
)


class Identity(Serializable, db.Model):
    """Abstract identity, superclass of Persona and Group

    Attributes:
        _insert_required: Attributes that are serialized
        id: 32 byte ID generated by uuid4().hex
        username: Public username of the Identity, max 80 bytes
        crypt_private: Private encryption RSA key, JSON encoded KeyCzar export
        crypt_public: Public encryption RSA key, JSON encoded KeyCzar export
        sign_private: Private signing RSA key, JSON encoded KeyCzar export
        sign_public: Public signing RSA key, JSON encoded KeyCzar export
        modified: Last time this Identity object was modified, defaults to now
        vesicles: List of Vesicles that describe this Identity object
        profile: Starmap containing this Identity's profile page

    """

    __tablename__ = "identity"

    _insert_required = ["id", "username", "crypt_public", "sign_public", "modified", "profile_id"]
    _update_required = ["id", "modified"]

    _stub = db.Column(db.Boolean, default=False)
    id = db.Column(db.String(32), primary_key=True)
    kind = db.Column(db.String(32))
    created = db.Column(db.DateTime)
    modified = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    username = db.Column(db.String(80))
    crypt_private = db.Column(db.Text)
    crypt_public = db.Column(db.Text)
    sign_private = db.Column(db.Text)
    sign_public = db.Column(db.Text)

    vesicles = db.relationship(
        'Vesicle',
        secondary='identity_vesicles',
        primaryjoin='identity_vesicles.c.identity_id==identity.c.id',
        secondaryjoin='identity_vesicles.c.vesicle_id==vesicle.c.id')

    profile_id = db.Column(db.String(32), db.ForeignKey('starmap.id'))
    profile = db.relationship('Starmap', backref="contexts", primaryjoin='starmap.c.id==identity.c.profile_id')

    __mapper_args__ = {
        'polymorphic_identity': 'identity',
        'polymorphic_on': kind
    }

    def __repr__(self):
        try:
            name = self.username.encode('utf-8')
        except AttributeError:
            name = ""
        return "<ID @{} [{}]>".format(name, self.id[:6])

    def authorize(self, action, author_id=None):
        """Return True if this Identity authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Identity ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        if Serializable.authorize(self, action, author_id=author_id):
            return (self.id == author_id)
        return False

    def controlled(self):
        """
        Return True if currently active User controls this Persona and
            all neccessary keys are available
        """
        if self.crypt_private is not None and self.sign_private is not None:
            if self.id == session["active_persona"]:
                return True
            if Persona.query.get(session["active_persona"]).user == self.user:
                return True
        else:
            return False

    @staticmethod
    def list_controlled():
        controlled_user = User.query.join(PersonaAssociation).filter(PersonaAssociation.right_id == session["active_persona"]).first()

        return [asc.persona for asc in controlled_user.associations]

    def generate_keys(self, password):
        """ Generate new RSA keypairs for signing and encrypting. Commit to DB afterwards! """

        # TODO: Store keys encrypted
        rsa1 = RsaPrivateKey.Generate()
        self.sign_private = str(rsa1)
        self.sign_public = str(rsa1.public_key)

        rsa2 = RsaPrivateKey.Generate()
        self.crypt_private = str(rsa2)
        self.crypt_public = str(rsa2.public_key)

    def encrypt(self, data):
        """ Encrypt data using RSA """

        key_public = RsaPublicKey.Read(self.crypt_public)
        return b64encode(key_public.Encrypt(data))

    def decrypt(self, cypher):
        """ Decrypt cyphertext using RSA """

        cypher = b64decode(cypher)
        key_private = RsaPrivateKey.Read(self.crypt_private)
        return key_private.Decrypt(cypher)

    def sign(self, data):
        """ Sign data using RSA """

        key_private = RsaPrivateKey.Read(self.sign_private)
        signature = key_private.Sign(data)
        return b64encode(signature)

    def verify(self, data, signature_b64):
        """ Verify a signature using RSA """

        signature = b64decode(signature_b64)
        key_public = RsaPublicKey.Read(self.sign_public)
        return key_public.Verify(data, signature)

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None, kind=None, request_sources=True):
        """See Serializable.create_from_changeset

        Args:
            kind (class): Pass a class to create new entity from
            request_sources (bool): Request linked objects
        """
        request_list = list()

        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)

        if stub:
            ident = stub
            ident.id = changeset["id"]
            ident.username = changeset["username"]
            ident.crypt_public = changeset["crypt_public"]
            ident.sign_public = changeset["sign_public"]
            ident.modified = modified_dt
            ident._stub = False
        else:
            if kind is None:
                kind = Identity

            ident = kind(
                id=changeset["id"],
                username=changeset["username"],
                crypt_public=changeset["crypt_public"],
                sign_public=changeset["sign_public"],
                modified=modified_dt,
            )

        # Update profile
        profile = Starmap.query.get(changeset["profile_id"])
        if profile is None or profile.get_state() == -1:
            request_list.append({
                "type": "Starmap",
                "id": changeset["profile_id"],
                "author_id": update_recipient.id if update_recipient else None,
                "recipient_id": update_sender.id if update_sender else None,
                "id": changeset["profile_id"]
            })

        if profile is None:
            profile = Starmap(id=changeset["profile_id"])
            profile.state = -1

        ident.profile = profile

        logger.info("Created {} from changeset, now requesting {} linked objects".format(
            ident, len(request_list)))

        if request_sources:
            for req in request_list:
                request_objects.send(Identity.create_from_changeset, message=req)
        else:
            logger.info("Not requesting linked sources for new {}".format(kind))

        return ident

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """See Serializable.update_from_changeset"""
        request_list = list()

        # Update modified
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        self.modified = modified_dt

        # Update username
        if "username" in changeset:
            self.username = changeset["username"]
            logger.info("Updated {}'s {}".format(self.username, "username"))

        # Update profile
        if "profile_id" in changeset:
            profile = Starmap.query.get(changeset["profile_id"])
            if profile is None or profile.get_state() == -1:
                request_list.append({
                    "type": "Starmap",
                    "id": changeset["profile_id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })
                logger.info("Requested {}'s {}".format(self.username, "profile starmap"))
            else:
                self.profile = profile
                logger.info("Updated {}'s {}".format(self.username, "profile starmap"))

        logger.info("Updated {} identity from changeset. Requesting {} objects.".format(self, len(request_list)))

        for req in request_list:
            request_objects.send(Identity.create_from_changeset, message=req)

#
# Setup follower relationship on Persona objects
#

t_contacts = db.Table('contacts',
    db.Column('left_id', db.String(32), db.ForeignKey('persona.id')),
    db.Column('right_id', db.String(32), db.ForeignKey('persona.id')),
    db.UniqueConstraint('left_id', 'right_id', name='_uc_contacts')
)

t_groups_followed = db.Table('groups_followed',
    db.Column('persona_id', db.String(32), db.ForeignKey('persona.id')),
    db.Column('group_id', db.String(32), db.ForeignKey('group.id'))
)


class Persona(Identity):
    """A Persona represents a user profile

    Attributes:
        email: An email address, max 120 bytes
        contacts: List of this Persona's contacts
        index: Starmap containing all Star's this Persona publishes to its contacts
        myelin_offset: Datetime of last request for Vesicles sent to this Persona

    """
    __mapper_args__ = {
        'polymorphic_identity': 'persona'
    }

    _insert_required = Identity._insert_required + ["email", "index_id", "contacts", "groups"]
    _update_required = Identity._update_required

    id = db.Column(db.String(32), db.ForeignKey('identity.id'), primary_key=True)
    email = db.Column(db.String(120))
    auth = db.Column(db.String(32), default=uuid4().hex)
    session_id = db.Column(db.String(32), default=uuid4().hex)
    last_connected = db.Column(db.DateTime, default=datetime.datetime.now())

    contacts = db.relationship('Persona',
        secondary='contacts',
        lazy="dynamic",
        remote_side='contacts.c.right_id',
        primaryjoin='contacts.c.left_id==persona.c.id',
        secondaryjoin='contacts.c.right_id==persona.c.id')

    groups_followed = db.relationship('Group',
        secondary='groups_followed',
        primaryjoin='groups_followed.c.persona_id==persona.c.id',
        secondaryjoin='groups_followed.c.group_id==group.c.id')

    index_id = db.Column(db.String(32), db.ForeignKey('starmap.id'))
    index = db.relationship('Starmap', primaryjoin='starmap.c.id==persona.c.index_id')

    # Myelin offset stores the date at which the last Vesicle receieved from Myelin was created
    myelin_offset = db.Column(db.DateTime)

    def __repr__(self):
        try:
            name = self.username.encode('utf-8')
        except AttributeError:
            name = ""
        return "<Persona @{} [{}]>".format(name, self.id[:6])

    def activate(self):
        if current_user.is_anonymous:
            return UnauthorizedError("Need to be logged in to activate Personas")

        if not self.associations[0].user == current_user:
            raise UnauthorizedError("You can't activate foreign Personas")

        for asc in PersonaAssociation.query.filter(PersonaAssociation.user==current_user, PersonaAssociation.active==True):
            if asc.active and not (asc == self.associations[0]):
                asc.active = False
                db.session.add(asc)

        self.associations[0].active = True
        db.session.add(self.associations[0])
        db.session.commit()

    def authorize(self, action, author_id=None):
        """Return True if this Persona authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        if Identity.authorize(self, action, author_id=author_id):
            return (self.id == author_id)
        return False

    def get_email_hash(self):
        """Return sha256 hash of this user's email address"""
        return sha256(self.email).hexdigest()

    def get_absolute_url(self):
        return url_for('persona', id=self.id)

    def export(self, exclude=[], include=None, update=False):
        exclude = set(exclude + ["contacts", "groups", "groups_followed"])
        data = Identity.export(self, exclude=exclude, include=include, update=update)

        data["contacts"] = list()
        for contact in self.contacts:
            data["contacts"].append({
                "id": contact.id,
            })

        data["groups"] = list()
        for group in self.groups:
            data["groups"].append({
                "id": group.id,
            })

        data["groups_followed"] = list()
        for group in self.groups_followed:
            data["groups_followed"].append({
                "id": group.id
            })

        return data

    def reset(self):
        """Reset session_id"""
        self.session_id = uuid4().hex
        self.auth = uuid4().hex
        return self.session_id

    def timeout(self):
        return self.last_connected + current_app.config['SESSION_EXPIRATION_TIME']

    @staticmethod
    def request_persona(persona_id):
        """Return a Persona profile, loading it from Glia if neccessary

        Args:
            persona_id (String): ID of the required Persona

        Returns:
            Persona: If a record was found
            None: If no record was found
        """
        from synapse import ElectricalSynapse
        electrical = ElectricalSynapse()
        return electrical.get_persona(persona_id)

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """See Serializable.create_from_changeset"""
        p = Identity.create_from_changeset(changeset,
            stub=stub, update_sender=update_sender, update_recipient=update_recipient, kind=Persona)

        request_list = list()

        p.email = changeset["email"]

        # Update index
        index = Starmap.query.get(changeset["index_id"])
        if index is None or index.get_state() == -1:
            request_list.append({
                "type": "Starmap",
                "id": changeset["index_id"],
                "author_id": update_recipient.id,
                "recipient_id": update_sender.id,
            })

        if index is None:
            index = Starmap(id=changeset["index_id"])
            index.state = -1

        p.index = index

        # Update contacts
        missing_contacts = p.update_contacts(changeset["contacts"])
        for mc in missing_contacts:
            request_list.append({
                "type": "Persona",
                "id": mc,
                "author_id": update_recipient.id,
                "recipient_id": update_sender.id,
            })

        # Request unknown groups
        groups_to_check = set(changeset["groups"] + changeset["groups_followed"])
        for group_info in groups_to_check:
            group = Group.query.get(group_info["id"])
            if group is None:
                request_list.append({
                    "type": "Group",
                    "id": group_info["id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })

        logger.info("Made {} a Persona object, now requesting {} linked objects".format(
            p, len(request_list)))

        for req in request_list:
            request_objects.send(Persona.create_from_changeset, message=req)

        return p

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """See Serializable.update_from_changeset"""
        Identity.update_from_changeset(self, changeset,
            update_sender=update_sender, update_recipient=update_recipient)

        logger.info("Now applying Persona-specific updates for {}".format(self))

        request_list = list()

        # Update email
        if "email" in changeset:
            if isinstance(changeset["email"], str):
                self.email = changeset["email"]
                logger.info("Updated {}'s {}".format(self.username, "email"))
            else:
                logger.warning("Invalid `email` supplied in update for {}\n\n".format(
                    self, changeset))

        # Update index
        if "index_id" in changeset:
            index = Starmap.query.get(changeset["index_id"])
            if index is None or index.get_state() == -1:
                request_list.append({
                    "type": "Starmap",
                    "id": changeset["index_id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })
                logger.info("Requested {}'s new {}".format(self.username, "index starmap"))
            else:
                self.index = index
                logger.info("Updated {}'s {}".format(self.username, "index starmap"))

        # Update contacts
        if "contacts" in changeset:
            missing_contacts = self.update_contacts(changeset["contacts"])
            for mc in missing_contacts:
                request_list.append({
                    "type": "Persona",
                    "id": mc,
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })

        # Request unknown groups
        groups_1 = changeset.get('groups') or []
        groups_2 = changeset.get('groups_followed') or []
        groups_to_check = groups_1 + groups_2

        for group_info in groups_to_check:
            group = Group.query.get(group_info["id"])
            if group is None:
                request_list.append({
                    "type": "Group",
                    "id": group_info["id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })

        logger.info("Updated {} from changeset. Requesting {} objects.".format(self, len(request_list)))

        for req in request_list:
            request_objects.send(Persona.update_from_changeset, message=req)

    def update_contacts(self, contact_list):
        """Update Persona's contacts from a list of the new contacts

        Args:
            contact_list (list): List of dictionaries with keys:
                id (String) -- 32 byte ID of the contact

        Returns:
            list: List of missing Persona IDs to be requested
        """
        updated_contacts = 0
        request_list = list()

        # stale_contacts contains all old contacts at first, all current
        # contacts get then removed so that the remaining can get deleted
        stale_contacts = set(self.contacts)

        for contact in contact_list:
            c = Persona.query.get(contact["id"])

            if c is None:
                c = Persona(id=contact["id"], _stub=True)

            if c._stub is True:
                request_list.append(contact["id"])

            try:
                # Old and new contact; remove from stale list
                stale_contacts.remove(c)
            except KeyError:
                # New contact
                self.contacts.append(c)
                updated_contacts += 1

        # Remove old contacts that are not new contacts
        for contact in stale_contacts:
            self.contacts.remove(contact)

        logger.info("Updated {}'s contacts: {} added, {} removed, {} requested".format(
            self.username, updated_contacts, len(stale_contacts), len(request_list)))

        return request_list

    @property
    def user(self):
        return self.associations[0].user

    def toggle_following_group(self, group):
        """Toggle whether this Persona is following a group.

        Args:
            group (Group): Group entity to be (un)followed

        Returns:
            boolean -- True if the group is now being followed, False if not
        """
        following = False

        try:
            self.groups_followed.remove(group)
        except ValueError:
            self.groups_followed.append(group)
            following = True

        return following


t_star_vesicles = db.Table(
    'star_vesicles',
    db.Column('star_id', db.String(32), db.ForeignKey('star.id')),
    db.Column('vesicle_id', db.String(32), db.ForeignKey('vesicle.id'))
)


class Star(Serializable, db.Model):
    """A Star represents a post"""

    __tablename__ = "star"

    _insert_required = ["id", "text", "created", "modified", "author_id", "planet_assocs", "parent_id"]
    _update_required = ["id", "text", "modified"]

    id = db.Column(db.String(32), primary_key=True)
    text = db.Column(db.Text)
    kind = db.Column(db.String(32))

    created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    modified = db.Column(db.DateTime, default=datetime.datetime.utcnow())

    state = db.Column(db.Integer, default=0)

    author = db.relationship('Identity',
        backref=db.backref('stars'),
        primaryjoin="identity.c.id==star.c.author_id")
    author_id = db.Column(db.String(32), db.ForeignKey('identity.id'))

    planet_assocs = db.relationship("PlanetAssociation",
        backref="star",
        lazy="dynamic")

    vesicles = db.relationship('Vesicle',
        secondary='star_vesicles',
        primaryjoin='star_vesicles.c.star_id==star.c.id',
        secondaryjoin='star_vesicles.c.vesicle_id==vesicle.c.id')

    parent = db.relationship('Star',
        primaryjoin='and_(remote(Star.id)==Star.parent_id, Star.state>=0)',
        backref=db.backref('children', lazy="dynamic"),
        remote_side='Star.id')
    parent_id = db.Column(db.String(32), db.ForeignKey('star.id'))

    __mapper_args__ = {
        'polymorphic_identity': 'star',
        'polymorphic_on': kind
    }

    def __repr__(self):
        try:
            ascii_text = self.text.encode('utf-8')
        except AttributeError:
            ascii_text = "No text content"
        return "<Star {}: {}>".format(
            self.id[:6],
            (ascii_text[:24] if len(ascii_text) <= 24 else ascii_text[:22] + ".."))

    def authorize(self, action, author_id=None):
        """Return True if this Star authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        if Serializable.authorize(self, action, author_id=author_id):
            return author_id == self.author.id
        return False

    @property
    def comments(self):
        return self.children.filter_by(kind="star")

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """See Serializable.create_from_changeset"""
        created_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)

        if stub is not None:
            star = stub
            star.text = changeset["text"]
            star.author = None
            star.created = created_dt
            star.modified = modified_dt
        else:
            star = Star(
                id=changeset["id"],
                text=changeset["text"],
                author=None,
                created=created_dt,
                modified=modified_dt,
            )

        author = Persona.query.get(changeset["author_id"])
        if author is None:
            # TODO: Send request for author
            star.author_id = changeset["author_id"]
        else:
            star.author = author

        # Append planets to new Star
        for planet_assoc in changeset["planet_assocs"]:
            if not PlanetAssociation.validate_changeset(planet_assoc):
                logger.warning("Invalid changeset for planet associated with {}\n\n{}".format(star, changeset))
            else:
                author = Persona.request_persona(planet_assoc["author_id"])
                pid = planet_assoc["planet"]["id"]

                # TODO: Better lookup method for planet classes
                if planet_assoc["planet"]["kind"] == "link":
                    planet_cls = LinkPlanet
                elif planet_assoc["planet"]["kind"] == "linkedpicture":
                    planet_cls = LinkedPicturePlanet
                elif planet_assoc["planet"]["kind"] == "text":
                    planet_cls = TextPlanet
                else:
                    raise NotImplementedError("Planet class {} is not implemented yet".format(
                        planet_assoc["planet"]["kind"]))

                planet = planet_cls.query.get(pid)
                if planet is None:
                    planet = planet_cls.create_from_changeset(planet_assoc["planet"])
                else:
                    planet.update_from_changeset(planet_assoc["planet"])

                assoc = PlanetAssociation(author=author, planet=planet)
                star.planet_assocs.append(assoc)
                logger.info("Added {} to new {}".format(planet, star))

        logger.info("Created {} from changeset".format(star))

        if changeset["parent_id"] != "None":
            parent = Star.query.get(changeset["parent_id"])
            if parent:
                star.parent = parent
            else:
                logger.info("Requesting {}'s parent star".format(star))
                request_objects.send(Star.create_from_changeset, message={
                    "type": "Star",
                    "id": changeset["parent_id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })

        return star

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a Star from a changeset (See Serializable.update_from_changeset)"""
        # Update modified
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        self.modified = modified_dt

        # Update text
        self.text = changeset["text"]

        for planet_assoc in changeset["planet_assocs"]:
            if not PlanetAssociation.validate_changeset(planet_assoc):
                logger.warning("Invalid changeset for planet associated with {}\n{}".format(self, changeset))
            else:
                author = Persona.request_persona(planet_assoc["author_id"])
                pid = planet_assoc["planet"]["id"]

                assoc = PlanetAssociation.filter_by(star_id=self.id).filter_by(planet_id=pid).first()
                if assoc is None:
                    planet = Planet.query.get(pid)
                    if planet is None:
                        planet = Planet.create_from_changeset(planet_assoc["planet"])
                    else:
                        planet.update_from_changeset(planet_assoc["planet"])

                    assoc = PlanetAssociation(author=author, planet=planet)
                    self.planet_assocs.append(assoc)
                    logger.info("Added {} to {}".format(planet, self))

        logger.info("Updated {} from changeset".format(self))

    def export(self, exclude=[], include=None, update=False):
        """See Serializable.export"""

        ex = set(exclude + ["planets", ])
        data = Serializable.export(self, exclude=ex, include=include, update=update)

        data["planet_assocs"] = list()
        for planet_assoc in self.planet_assocs:
            data["planet_assocs"].append({
                "planet": planet_assoc.planet.export(),
                "author_id": planet_assoc.author_id
            })

        return data

    def get_state(self):
        """
        Return publishing state of this star.

        Returns:
            Integer:
                -2 -- deleted
                -1 -- unavailable
                0 -- published
                1 -- draft
                2 -- private
                3 -- updating
        """
        return STAR_STATES[self.state][0]

    def set_state(self, new_state):
        """
        Set the publishing state of this star

        Parameters:
            new_state (int) code of the new state as defined in nucleus.STAR_STATES

        Raises:
            ValueError: If new_state is not an Int or not a valid state of this object
        """
        new_state = int(new_state)
        if new_state not in STAR_STATES.keys():
            raise ValueError("{} ({}) is not a valid star state").format(
                new_state, type(new_state))
        else:
            self.state = new_state

    def get_absolute_url(self):
        return url_for('star', id=self.id)

    def hot(self):
        """i reddit"""
        from math import log
        # Uncomment to assign a score with analytics.score
        # s = score(self)
        s = self.oneup_count()
        order = log(max(abs(s), 1), 10)
        sign = 1 if s > 0 else -1 if s < 0 else 0
        return round(order + sign * epoch_seconds(self.created) / 45000, 7)

    @property
    def oneups(self):
        """Returns a query for all oneups, including disabled ones"""
        return self.children.filter_by(kind="oneup")

    def oneupped(self):
        """
        Return True if active Persona has 1upped this Star
        """

        oneup = self.oneups.filter_by(author=current_user.active_persona).first()

        if oneup is None or oneup.state < 0:
            return False
        else:
            return True

    def oneup_count(self):
        """
        Return the number of verified upvotes this Star has receieved

        Returns:
            Int: Number of upvotes
        """
        return self.oneups.filter(Oneup.state >= 0).count()

    def comment_count(self):
        """
        Return the number of comemnts this Star has receieved

        Returns:
            Int: Number of comments
        """
        return self.comments.filter_by(state=0).count()

    def toggle_oneup(self, author_id=None):
        """
        Toggle 1up for this Star on/off

        Args:
            author_id (String): Optional Persona ID that issued the 1up. Defaults to active Persona.

        Returns:
            Oneup: The toggled oneup object

        Raises:
            PersonaNotFoundError: 1up author not found
            UnauthorizedError: Author is a foreign Persona
        """

        if author_id is None:
            author = current_user.active_persona
        else:
            author = Persona.query.get(author_id)

        if author is None:
            raise PersonaNotFoundError("1up author not found")

        if not author.controlled():
            raise UnauthorizedError("Can't toggle 1ups with foreign Persona {}".format(author))

        # Check whether 1up has been previously issued
        oneup = self.oneups.filter_by(author=author).first()
        if oneup is not None:
            old_state = oneup.get_state()
            oneup.set_state(-1) if oneup.state == 0 else oneup.set_state(0)
        else:
            old_state = False
            oneup = Oneup(id=uuid4().hex, author=author, parent=self)
            self.children.append(oneup)

        # Commit 1up
        db.session.add(self)
        db.session.commit()
        logger.info("{verb} {obj}".format(verb="Toggled" if old_state else "Added", obj=oneup, ))

        return oneup

    def link_url(self):
        """Return URL if this Star has a Link-Planet

        Returns:
            String: URL of the first associated Link
            Bool: False if no link was found
        """
        # planet_assoc = self.planet_assocs.join(PlanetAssociation.planet.of_type(LinkPlanet)).first()

        for planet_assoc in self.planet_assocs:
            if planet_assoc.planet.kind == "link":
                return planet_assoc.planet.url
        return None

    def has_picture(self):
        """Return True if this Star has a PicturePlanet"""
        try:
            first = self.picture_planets()[0]
        except IndexError:
            first = None

        return first is not None

    def has_text(self):
        """Return True if this Star has a TextPlanet"""
        try:
            first = self.text_planets()[0]
        except IndexError:
            first = None

        return first is not None

    def picture_planets(self):
        """Return pictures of this Star"""
        return self.planet_assocs.join(PlanetAssociation.planet.of_type(LinkedPicturePlanet)).all()

    def text_planets(self):
        """Return TextPlanets of this Star"""
        return self.planet_assocs.join(PlanetAssociation.planet.of_type(TextPlanet)).all()


class PlanetAssociation(db.Model):
    """Associates Planets with Stars, defining an author for the connection"""

    __tablename__ = 'planet_association'
    star_id = db.Column(db.String(32), db.ForeignKey('star.id'), primary_key=True)
    planet_id = db.Column(db.String(32), db.ForeignKey('planet.id'), primary_key=True)
    planet = db.relationship("Planet", backref="star_assocs")
    author_id = db.Column(db.String(32), db.ForeignKey('persona.id'))
    author = db.relationship("Persona", backref="planet_assocs")

    @classmethod
    def validate_changeset(cls, changeset):
        """Return True if `changeset` is a valid PlanetAssociation changeset"""

        if "author_id" not in changeset or changeset["author_id"] is None:
            logger.warning("Missing `author_id` in changeset")
            return False

        if "planet" not in changeset or changeset["planet"] is None or "kind" not in changeset["planet"]:
            logger.warning("Missing `planet` or `planet.kind` in changeset")
            return False

        p_cls = LinkPlanet if changeset["planet"]["kind"] == "link" else LinkedPicturePlanet
        return p_cls.validate_changeset(changeset)

    @property
    def sort_rank(self):
        """Return sort rank of this planet type

        Returns:
            Depending on self.__class__ an Integer > 0 is returned
        """
        return planet_sort_rank.get(self.planet.kind, 1000)


t_planet_vesicles = db.Table(
    'planet_vesicles',
    db.Column('planet_id', db.String(32), db.ForeignKey('planet.id')),
    db.Column('vesicle_id', db.String(32), db.ForeignKey('vesicle.id'))
)


class Planet(Serializable, db.Model):
    """A Planet represents an attachment"""

    __tablename__ = 'planet'

    _insert_required = ["id", "title", "created", "modified", "source", "kind"]
    _update_required = ["id", "title", "modified", "source"]

    id = db.Column(db.String(32), primary_key=True)
    title = db.Column(db.Text)
    kind = db.Column(db.String(32))
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    modified = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    source = db.Column(db.String(128))
    state = db.Column(db.Integer, default=0)

    vesicles = db.relationship(
        'Vesicle',
        secondary='planet_vesicles',
        primaryjoin='planet_vesicles.c.planet_id==planet.c.id',
        secondaryjoin='planet_vesicles.c.vesicle_id==vesicle.c.id')

    __mapper_args__ = {
        'polymorphic_identity': 'planet',
        'polymorphic_on': kind
    }

    def __repr__(self):
        return "<Planet:{} [{}]>".format(self.kind, self.id[:6])

    def get_state(self):
        """
        Return publishing state of this planet.

        Returns:
            Integer:
                -2 -- deleted
                -1 -- unavailable
                0 -- published
                1 -- draft
                2 -- private
                3 -- updating
        """
        return PLANET_STATES[self.state][0]

    def set_state(self, new_state):
        """
        Set the publishing state of this planet

        Parameters:
            new_state (int) code of the new state as defined in nucleus.PLANET_STATES

        Raises:
            ValueError: If new_state is not an Int or not a valid state of this object
        """
        new_state = int(new_state)
        if new_state not in PLANET_STATES.keys():
            raise ValueError("{} ({}) is not a valid planet state").format(
                new_state, type(new_state))
        else:
            self.state = new_state

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Planet object from a changeset (See Serializable.create_from_changeset). """
        created_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)

        if stub is not None:
            if not isinstance(stub, Planet):
                raise ValueError("Invalid stub of type {}".format(type(stub)))

            new_planet = stub
            new_planet.id = changeset["id"]
            new_planet.title = changeset["title"]
            new_planet.source = changeset["source"]
            new_planet.created = created_dt
            new_planet.modified = modified_dt
        else:
            new_planet = Planet(
                id=changeset["id"],
                title=changeset["title"],
                created=created_dt,
                modified=modified_dt,
                source=changeset["source"]
            )

        logger.info("Created new {} from changeset".format(new_planet))
        return new_planet

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a new Planet object from a changeset (See Serializable.update_from_changeset). """
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)

        self.title = changeset["title"]
        self.source = changeset["source"]
        self.modifed = modified_dt

        return self


class PicturePlanet(Planet):
    """A Picture attachment"""

    _insert_required = ["id", "title", "created", "modified", "source", "filename", "kind"]
    _update_required = ["id", "title", "modified", "source", "filename"]

    id = db.Column(db.String(32), db.ForeignKey('planet.id'), primary_key=True)
    filename = db.Column(db.Text)

    __mapper_args__ = {
        'polymorphic_identity': 'picture'
    }

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Planet object from a changeset (See Serializable.create_from_changeset). """
        stub = PicturePlanet()

        new_planet = Planet.create_from_changeset(changeset,
            stub=stub, update_sender=update_sender, update_recipient=update_recipient)

        new_planet.filename = changeset["filename"]

        return new_planet

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a new Planet object from a changeset (See Serializable.update_from_changeset). """
        raise NotImplementedError


class LinkedPicturePlanet(Planet):
    """A linked picture attachment"""

    _insert_required = ["id", "title", "created", "modified", "source", "url", "kind"]
    _update_required = ["id", "title", "modified", "source", "url"]

    id = db.Column(db.String(32), db.ForeignKey('planet.id'), primary_key=True)
    url = db.Column(db.Text)
    # width = db.Column(db.Integer, default=0)
    # height = db.Column(db.Integer, default=0)

    __mapper_args__ = {
        'polymorphic_identity': 'linkedpicture'
    }

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Planet object from a changeset (See Serializable.create_from_changeset). """
        if stub is None:
            stub = LinkedPicturePlanet()

        new_planet = Planet.create_from_changeset(changeset,
            stub=stub, update_sender=update_sender, update_recipient=update_recipient)

        new_planet.url = changeset["url"]

        # if "width" in changeset:
        #     new_planet.width = int(changeset["width"])

        # if "height" in changeset:
        #     new_planet.height = int(changeset["height"])

        return new_planet

    @classmethod
    def get_or_create(cls, url, *args, **kwargs):
        """Get or create an instance from a URL

        Args:
            url (String): URL of the Planet to retrieve
            args, kwargs: get passed on to cls.__init__ if a new instance is created

        Raises:
            ValueError: If no url was provided"""

        if url is not None:
            url_hash = sha256("linkedpicture" + url).hexdigest()[:32]
        else:
            raise ValueError("URL parameter must not be None")

        inst = cls.query.filter_by(id=url_hash).first()
        if inst is None:
            inst = cls(id=url_hash, url=url, *args, **kwargs)

        return inst

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a new Planet object from a changeset (See Serializable.update_from_changeset). """
        raise NotImplementedError


class LinkPlanet(Planet):
    """A URL attachment"""

    _insert_required = ["id", "title", "kind", "created", "modified", "source", "url", "kind"]
    _update_required = ["id", "title", "modified", "source", "url"]

    id = db.Column(db.String(32), db.ForeignKey('planet.id'), primary_key=True)
    url = db.Column(db.Text)

    __mapper_args__ = {
        'polymorphic_identity': 'link'
    }

    @classmethod
    def get_or_create(cls, url, title=None):
        """Get or create an instance from a URL

        Args:
            url (String): URL of the Planet to retrieve
            title (String): Optional title. Is only set when no existing
                instance is found

        Raises:
            ValueError: If no url was provided"""

        if url is not None:
            url_hash = sha256(url).hexdigest()[:32]
        else:
            raise ValueError("URL parameter must not be None")

        inst = cls.query.filter_by(id=url_hash).first()
        if inst is None:
            inst = cls(id=url_hash, url=url, title=title)

        return inst

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Planet object from a changeset (See Serializable.create_from_changeset). """
        if stub is None:
            stub = LinkPlanet()

        new_planet = Planet.create_from_changeset(changeset,
            stub=stub, update_sender=update_sender, update_recipient=update_recipient)

        new_planet.url = changeset["url"]

        return new_planet

    def favicon_url(self):
        """Return the URL of this Planet's domain favicon

        Returns:
            string: URL of the favicon as a 32 pixel image"""

        # Taken from http://stackoverflow.com/questions/9626535/get-domain-name-from-url/9626596#9626596

        from urlparse import urlparse

        parsed_uri = urlparse(self.url)
        try:
            domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
        except AttributeError, e:
            logger.warning("Error retrieving domain for {}: {}".format(self, e))
        else:
            return "http://grabicon.com/icon?domain={}".format(domain)

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a new Planet object from a changeset (See Serializable.update_from_changeset). """
        raise NotImplementedError


class TextPlanet(Planet):
    """A longform text attachment"""

    _insert_required = ["id", "title", "kind", "created", "modified", "source", "text", "kind"]
    _update_required = ["id", "title", "modified", "source", "text"]

    id = db.Column(db.String(32), db.ForeignKey('planet.id'), primary_key=True)
    text = db.Column(db.Text)

    __mapper_args__ = {
        'polymorphic_identity': 'text'
    }

    @classmethod
    def get_or_create(cls, text):
        """Return planet containing text if it already exists or create it

        Args:
            text: Content value of the TextPlanet
        """
        h = sha256(text.encode('utf-8')).hexdigest()[:32]
        planet = TextPlanet.query.get(h)

        if planet is None:
            logger.info("Storing new text")
            planet = TextPlanet(
                id=h,
                text=text)

        return planet

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Planet object from a changeset (See Serializable.create_from_changeset). """
        if stub is None:
            stub = TextPlanet()

        new_planet = Planet.create_from_changeset(changeset,
            stub=stub, update_sender=update_sender, update_recipient=update_recipient)

        new_planet.text = changeset["text"]

        return new_planet

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a new Planet object from a changeset (See Serializable.update_from_changeset). """
        raise NotImplementedError

    def reading_time(self):
        """Return an estimate for reading time based on 200 words per minute

        Returns:
            Reading time as a timedelta object
        """
        word_count = len(self.text.split(" "))
        return datetime.timedelta(minutes=int(word_count / 200))


class Oneup(Star):
    """A 1up is a vote that signals interest in its parent Star"""

    _insert_required = ["id", "created", "modified", "author_id", "parent_id", "state"]
    _update_required = ["id", "modified", "state"]

    __mapper_args__ = {
        'polymorphic_identity': 'oneup'
    }

    def __repr__(self):
        if ["author_id", "parent_id"] in dir(self):
            return "<1up <Persona {}> -> <Star {}> ({})>".format(
                self.author_id[:6], self.parent_id[:6], self.get_state())
        else:
            return "<1up ({})>".format(self.get_state())

    def get_state(self):
        """
        Return publishing state of this 1up.

        Returns:
            Integer:
                -1 -- (disabled)
                 0 -- (active)
                 1 -- (unknown author)
        """
        return ONEUP_STATES[self.state][0]

    def set_state(self, new_state):
        """
        Set the publishing state of this 1up

        Parameters:
            new_state (int) code of the new state as defined in nucleus.ONEUP_STATES

        Raises:
            ValueError: If new_state is not an Int or not a valid state of this object
        """
        new_state = int(new_state)
        if new_state not in ONEUP_STATES.keys():
            raise ValueError("{} ({}) is not a valid 1up state".format(
                new_state, type(new_state)))
        else:
            self.state = new_state

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Oneup object from a changeset (See Serializable.create_from_changeset). """
        created_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)

        if stub is not None:
            oneup = stub
            oneup.created = created_dt
            oneup.modified = modified_dt
            oneup.author = None
            oneup.source = changeset["source"],
            oneup.parent_id = None
        else:
            oneup = Oneup(
                id=changeset["id"],
                created=created_dt,
                modified=modified_dt,
                author=None,
                parent=None,
            )

        oneup.set_state(int(changeset["state"]))

        author = Persona.query.get(changeset["author_id"])
        if author is None:
            # TODO: Send request for author
            oneup.author_id = changeset["author_id"]
            if oneup.get_state() >= 0:
                oneup.set_state(1)
        else:
            oneup.author = author

        star = Star.query.get(changeset["parent_id"])
        if star is None:
            logger.warning("Parent Star for Oneup not found")
            oneup.parent_id = changeset["parent_id"]
        else:
            star.children.append(oneup)

        return oneup

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a new Oneup object from a changeset (See Serializable.update_from_changeset). """
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        self.modified = modified_dt

        self.set_state(changeset["state"])

        logger.info("Updated {} from changeset".format(self))


class Souma(Serializable, db.Model):
    """A physical machine in the Souma network"""

    __tablename__ = "souma"

    _insert_required = ["id", "modified", "crypt_public", "sign_public", "starmap_id"]
    id = db.Column(db.String(32), primary_key=True)

    crypt_private = db.Column(db.Text)
    crypt_public = db.Column(db.Text)
    sign_private = db.Column(db.Text)
    sign_public = db.Column(db.Text)

    starmap_id = db.Column(db.String(32), db.ForeignKey('starmap.id'))
    starmap = db.relationship('Starmap')

    _version_string = db.Column(db.String(32), default="")

    def __str__(self):
        return "<Souma [{}]>".format(self.id[:6])

    def authorize(self, action, author_id=None):
        """Return True if this Souma authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        return False

    def authentic_request(self, request):
        """Validate whether a request carries a valid authentication
        Args:
            request: A Flask request context
        Raises:
            ValueError: If authentication fails
        """
        pass
        # if request.headers.get("X-Forwarded-Proto") == "https":
        #     url = str(request.url).replace("http://", "https://")
        # else:
        #     url = str(request.url)

        # glia_rand = b64decode(request.headers["Glia-Rand"])
        # glia_auth = request.headers["Glia-Auth"]
        # req = "".join([str(self.id), glia_rand, url, request.data])
        # if not self.verify(req, glia_auth):
        #     raise ValueError("""Request failed authentication: {}
        #         ID: {}
        #         Rand: {}
        #         Path: {}
        #         Payload: {} ({} bytes)
        #         Authentication: {} ({} bytes)""".format(request, str(self.id), b64encode(glia_rand), url, request.data[:400], len(request.data), glia_auth[:8], len(glia_auth)))

    def generate_keys(self):
        """ Generate new RSA keypairs for signing and encrypting. Commit to DB afterwards! """

        # TODO: Store keys encrypted
        rsa1 = RsaPrivateKey.Generate()
        self.sign_private = str(rsa1)
        self.sign_public = str(rsa1.public_key)

        rsa2 = RsaPrivateKey.Generate()
        self.crypt_private = str(rsa2)
        self.crypt_public = str(rsa2.public_key)

    def encrypt(self, data):
        """ Encrypt data using RSA """

        if self.crypt_public == "":
            raise ValueError("Error encrypting: No public encryption key found for {}".format(self))

        key_public = RsaPublicKey.Read(self.crypt_public)
        return key_public.Encrypt(data)

    def decrypt(self, cypher):
        """ Decrypt cyphertext using RSA """

        if self.crypt_private == "":
            raise ValueError("Error decrypting: No private encryption key found for {}".format(self))

        key_private = RsaPrivateKey.Read(self.crypt_private)
        return key_private.Decrypt(cypher)

    @property
    def version(self):
        """Return semantic version object for this Souma"""
        if not hasattr(self, "_version_string"):
            return None
        return semantic_version.Version(self._version_string)

    @version.setter
    def version(self, value):
        self._version_string = str(semantic_version.Version(value))

    def sign(self, data):
        """ Sign data using RSA """
        from base64 import urlsafe_b64encode

        if self.sign_private == "":
            raise ValueError("Error signing: No private signing key found for {}".format(self))

        key_private = RsaPrivateKey.Read(self.sign_private)
        signature = key_private.Sign(data)
        return urlsafe_b64encode(signature)

    def verify(self, data, signature_b64):
        """ Verify a signature using RSA """
        from base64 import urlsafe_b64decode

        if self.sign_public == "":
            raise ValueError("Error verifying: No public signing key found for {}".format(self))

        signature = urlsafe_b64decode(signature_b64)
        key_public = RsaPublicKey.Read(self.sign_public)
        return key_public.Verify(data, signature)

t_starmap = db.Table(
    'starmap_index',
    db.Column('starmap_id', db.String(32), db.ForeignKey('starmap.id')),
    db.Column('star_id', db.String(32), db.ForeignKey('star.id'))
)

t_starmap_vesicles = db.Table(
    'starmap_vesicles',
    db.Column('starmap_id', db.String(32), db.ForeignKey('starmap.id')),
    db.Column('vesicle_id', db.String(32), db.ForeignKey('vesicle.id'))
)


class Starmap(Serializable, db.Model):
    """
    Starmaps are collections of objects with associated layout information.

    Atributes:
        id: 32 byte ID generated by uuid4().hex
        modified: Datetime of last recorded modification
        author: Persona that created this Starmap
        kind: For what kind of context is this Starmap used
        index: List of Stars that are contained in this Starmap
        vesicles: List of Vesicles that describe this Starmap
    """
    __tablename__ = 'starmap'

    _insert_required = ["id", "modified", "author_id", "kind", "state"]
    _update_required = ["id", "modified", "index"]

    id = db.Column(db.String(32), primary_key=True)
    modified = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    kind = db.Column(db.String(16))
    state = db.Column(db.Integer, default=0)

    author_id = db.Column(
        db.String(32),
        db.ForeignKey('persona.id', use_alter=True, name="fk_author_id"))
    author = db.relationship('Persona',
        backref=db.backref('starmaps'),
        primaryjoin="Persona.id==Starmap.author_id",
        post_update=True)

    index = db.relationship(
        'Star',
        secondary='starmap_index',
        backref="starmaps",
        lazy="dynamic",
        primaryjoin='starmap_index.c.starmap_id==starmap.c.id',
        secondaryjoin='starmap_index.c.star_id==star.c.id')

    vesicles = db.relationship(
        'Vesicle',
        secondary='starmap_vesicles',
        primaryjoin='starmap_vesicles.c.starmap_id==starmap.c.id',
        secondaryjoin='starmap_vesicles.c.vesicle_id==vesicle.c.id')

    def __contains__(self, key):
        """Return True if the given key is contained in this Starmap.

        Args:
            key: db.model.key to look for
        """
        return (key in self.index)

    def __repr__(self):
        if self.kind == "persona_profile":
            name = "Persona-Profile"
        elif self.kind == "group_profile":
            name = "Group-Profile"
        else:
            name = "Starmap"

        return "<{} (by {}) [{}]>".format(name, self.author, self.id[:6])

    def __len__(self):
        return self.index.paginate(1).total

    def authorize(self, action, author_id=None):
        """Return True if this Starmap authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        if Serializable.authorize(self, action, author_id=author_id):
            if self.kind == "persona_profile":
                p = Persona.request_persona(self.author_id)
                return p.id == author_id
            elif self.kind == "group_profile":
                # Everyone can update
                if action == "update":
                    return True
                # Only author can insert and delete
                elif self.author_id == author_id:
                    return True

            elif self.kind == "index":
                p = Persona.query.filter(Persona.index_id == self.id)
                return p.id == author_id
        return False

    def get_state(self):
        """
        Return publishing state of this star.

        Returns:
            Integer:
                -2 -- deleted
                -1 -- unavailable
                0 -- published
                1 -- draft
                2 -- private
                3 -- updating
        """
        return STAR_STATES[self.state][0]

    def set_state(self, new_state):
        """
        Set the publishing state of this star

        Parameters:
            new_state (int) code of the new state as defined in nucleus.STAR_STATES

        Raises:
            ValueError: If new_state is not an Int or not a valid state of this object
        """
        new_state = int(new_state)
        if new_state not in STAR_STATES.keys():
            raise ValueError("{} ({}) is not a valid star state").format(
                new_state, type(new_state))
        else:
            self.state = new_state

    def get_absolute_url(self):
        """Return URL for this Starmap depending on kind"""
        if self.kind == "persona_profile":
            p = Persona.query.filter(Persona.profile_id == self.id).first()
            return url_for("persona", id=p.id)
        elif self.kind == "group_profile":
            g = Group.query.filter(Group.profile_id == self.id).first()
            return url_for("group", id=g.id)
        elif self.kind == "index":
            p = Persona.query.filter(Persona.index_id == self.id).first()
            return url_for("persona", id=p.id)

    def export(self, exclude=[], include=None, update=False):
        ex = set(exclude + ["index", ])
        data = Serializable.export(self, exclude=ex, include=include, update=update)

        data["index"] = list()
        for star in self.index.filter('Star.state >= 0'):
            data["index"].append({
                "id": star.id,
                "modified": star.modified.isoformat(),
                "author_id": star.author.id
            })

        return data

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Starmap object from a changeset

        Args:
            changeset (dict): Contains all keys from self._insert_required

        Returns:
            Starmap: The new object

        Raises:
            ValueError: If a value is invalid
            KeyError: If a required Value is missing
        """
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)

        author = Persona.query.get(changeset["author_id"])
        if author is None:
            raise PersonaNotFoundError("Starmap author not known")

        if stub is not None:
            new_starmap = stub
            new_starmap.modified = modified_dt
            new_starmap.author = author
            new_starmap.kind = changeset["kind"]
        else:
            new_starmap = Starmap(
                id=changeset["id"],
                modified=modified_dt,
                author=author,
                kind=changeset["kind"]
            )

        request_list = list()
        for star_changeset in changeset["index"]:
            star = Star.query.get(star_changeset["id"])
            star_changeset_modified = iso8601.parse_date(star_changeset["modified"]).replace(tzinfo=None)

            if star is None or star.get_state() == -1 or star.modified < star_changeset_modified:
                request_list.append({
                    "type": "Star",
                    "id": star_changeset["id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })

                if star is None:
                    star_author = Persona.query.get(star_changeset["author_id"])
                    if star_author is not None:
                        star = Star(
                            id=star_changeset["id"],
                            modified=star_changeset_modified,
                            author=star_author
                        )
                        star.set_state(-1)
                        db.session.add(star)
                        db.session.commit()

            new_starmap.index.append(star)

        db.session.add(new_starmap)
        db.session.commit()

        for req in request_list:
            request_objects.send(Starmap.create_from_changeset, message=req)

        return new_starmap

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update the Starmap's index using a changeset

        Args:
            changeset (dict): Contains a key for every attribute to update

        Raises:
            ValueError: If a value in the changeset is invalid
        """
        # Update modified
        modified = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        self.modified = modified

        # Update index
        remove_stars = set([s.id for s in self.index if s is not None])
        added_stars = list()
        request_list = list()
        for star_changeset in changeset["index"]:
            star = Star.query.get(star_changeset["id"])
            star_changeset_modified = iso8601.parse_date(star_changeset["modified"]).replace(tzinfo=None)

            if star is not None and star.id in remove_stars:
                remove_stars.remove(star.id)

            if star is None or star.get_state() == -1 or star.modified < star_changeset_modified:
                # No copy of Star available or copy is outdated

                request_list.append({
                    "type": "Star",
                    "id": star_changeset["id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })

                if star is None:
                    star_author = Persona.query.get(star_changeset["author_id"])
                    if star_author is not None:
                        star = Star(
                            id=star_changeset["id"],
                            modified=star_changeset_modified,
                            author=star_author
                        )
                        star.set_state(-1)
                        db.session.add(star)
                        db.session.commit()

            self.index.append(star)
            added_stars.append(star)

        for s_id in remove_stars:
            s = Star.query.get(s_id)
            self.index.remove(s)

        logger.info("Updated {}: {} stars added, {} requested, {} removed".format(
            self, len(added_stars), len(request_list), len(remove_stars)))

        for req in request_list:
            request_objects.send(Starmap.create_from_changeset, message=req)

#
# Table of group members
#

t_members = db.Table(
    'members',
    db.Column('group_id', db.String(32), db.ForeignKey('group.id')),
    db.Column('persona_id', db.String(32), db.ForeignKey('persona.id'))
)

t_group_vesicles = db.Table(
    'group_vesicles',
    db.Column('group_id', db.String(32), db.ForeignKey('group.id')),
    db.Column('vesicle_id', db.String(32), db.ForeignKey('vesicle.id'))
)


class Group(Identity):
    """Represents an entity that is comprised of users collaborating on stars

    Attributes:
        id (String): 32 byte ID of this group
        description (String): Text decription of what this group is about
        admin (Persona): Person that is allowed to make structural changes to the group_id

    """

    __tablename__ = "group"
    __mapper_args__ = {'polymorphic_identity': 'group'}

    _insert_required = Identity._insert_required + ["admin_id", "description", "profile_id"]
    _update_required = Identity._update_required + ["state"]

    id = db.Column(db.String(32), db.ForeignKey('identity.id'), primary_key=True)
    description = db.Column(db.Text)

    state = db.Column(db.Integer, default=0)

    admin_id = db.Column(db.String(32), db.ForeignKey('persona.id'))
    admin = db.relationship("Persona", primaryjoin="persona.c.id==group.c.admin_id")

    members = db.relationship('Persona',
        secondary='members',
        lazy="dynamic",
        backref="groups",
        primaryjoin='members.c.group_id==group.c.id',
        secondaryjoin='members.c.persona_id==persona.c.id')

    def __init__(self, *args, **kwargs):
        """Attach index starmap to new groups"""
        Identity.__init__(self, *args, **kwargs)
        index = Starmap(
            id=uuid4().hex,
            author=self.admin,
            kind="group_profile",
            modified=self.created)

        self.profile = index

    def __repr__(self):
        try:
            name = self.username.encode('utf-8')
        except AttributeError:
            name = "(name encode error)"

        return "<Group @{} [{}]>".format(name, self.id[:6])

    def add_member(self, persona):
        """Add a Persona as member to this group

        Args:
            persona (Persona): Persona object to be added
        """
        if persona not in self.members:
            self.members.append(persona)

    def authorize(self, action, author_id=None):
        """Return True if this Group authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        if Serializable.authorize(self, action, author_id=author_id):
            return self.admin_id == author_id
        return False

    def export(self, exclude=[], include=None, update=False):
        if not exclude:
            exclude = list()

        data = Identity.export(self, exclude=set(exclude + ["members"]), include=include, update=update)

        if "members" not in exclude:
            data["members"] = list()
            for m in self.members:
                data["members"].append({
                    "id": m.id,
                })

        return data

    def get_state(self):
        """
        Return publishing state of this Group. (temporarily uses planet states)

        Returns:
            Integer:
                -2 -- deleted
                -1 -- unavailable
                0 -- published
                1 -- draft
                2 -- private
                3 -- updating
        """
        return PLANET_STATES[self.state][0]

    def remove_member(self, persona):
        """Remove a Persona from this group's local member list

        Args:
            persona (Persona): Persona object to be removed
        """
        if persona in self.members:
            self.members.remove(persona)

    def set_state(self, new_state):
        """
        Set the publishing state of this Group (temporarily uses planet states)

        Parameters:
            new_state (int) code of the new state as defined in nucleus.PLANET_STATES

        Raises:
            ValueError: If new_state is not an Int or not a valid state of this object
        """
        new_state = int(new_state)
        if new_state not in PLANET_STATES.keys():
            raise ValueError("{} ({}) is not a valid planet state").format(
                new_state, type(new_state))
        else:
            self.state = new_state

    def update_members(self, new_member_list):
        """Update Groups's members from a list of the new members.

        This method may only be used with an authoritative list of group
        members (i.e. from the group admin).

        Args:
            new_member_list (list): List of dictionaries with keys:
                id (String) -- 32 byte ID of the member

        Returns:
            list: List of missing Persona IDs to be requested
        """
        updated_members = 0
        request_list = list()

        # stale_members contains all old members at first, all current
        # members get then removed so that the remaining can get deleted
        stale_members = set(self.members)

        for member in new_member_list:
            m = Persona.query.get(member["id"])

            if m is None:
                m = Persona(id=member["id"], _stub=True)

            if m._stub is True:
                request_list.append(member["id"])

            try:
                # Old and new member; remove from stale list
                stale_members.remove(m)
            except KeyError:
                # New member
                self.members.append(m)
                updated_members += 1

        # Remove old members that are not new members
        for member in stale_members:
            self.members.remove(member)

        logger.info("Updated {}'s members: {} added, {} removed, {} requested".format(
            self.username, updated_members, len(stale_members), len(request_list)))

        return request_list

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None, request_sources=True):
        """Create a new group from changeset"""
        group = Identity.create_from_changeset(changeset,
            stub=stub,
            update_sender=update_sender,
            update_recipient=update_recipient,
            kind=Group,
            request_sources=request_sources)

        group.description = changeset["description"]

        if "state" in changeset:
            group.set_state(changeset["state"])

        request_list = list()

        # Update admin
        admin = Persona.query.get(changeset["admin_id"])
        if admin is None or admin._stub:
            request_list.append({
                "type": "Persona",
                "id": changeset["admin_id"],
                "author_id": update_recipient.id if update_recipient else None,
                "recipient_id": update_sender.id if update_sender else None,
            })

        if admin is None:
            admin = Persona(
                id=changeset["admin_id"],
            )
            admin._stub = True

        group.admin = admin

        if "members" in changeset:
            mc = group.update_members(changeset["members"])
            for m in mc:
                request_list.append({
                    "type": "Persona",
                    "id": m,
                    "author_id": update_recipient.id if update_recipient else None,
                    "recipient_id": update_sender.id if update_sender else None,
                })

        if request_sources:
            for req in request_list:
                request_objects.send(Group.create_from_changeset, message=req)

        return group

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update group. See Serializable.update_from_changeset"""
        Identity.update_from_changeset(self, changeset,
            update_sender=update_sender, update_recipient=update_recipient)

        logger.info("Now applying Group-specific updates for {}".format(self))

        request_list = list()

        self.set_state(changeset["state"])

        if "description" in changeset:
            self.description = changeset["description"]
            logger.info("Updated {}'s description".format(self))

        if "admin_id" in changeset:
            admin = Persona.query.get(changeset["admin_id"])
            if admin is None or admin._stub:
                request_list.append({
                    "type": "Persona",
                    "id": changeset["admin_id"],
                    "author_id": update_recipient.id if update_recipient else None,
                    "recipient_id": update_sender.id if update_sender else None,
                })

            if admin is None:
                admin = Persona(
                    id=changeset["admin_id"],
                )
                admin._stub = True

            self.admin = admin

        if "members" in changeset:
            mc = self.update_members(changeset["members"])
            for m in mc:
                request_list.append({
                    "type": "Persona",
                    "id": m["id"],
                    "author_id": update_recipient.id if update_recipient else None,
                    "recipient_id": update_sender.id if update_sender else None,
                })

        logger.info("Updated {} from changeset. Requesting {} objects.".format(self, len(request_list)))

        for req in request_list:
            request_objects.send(Group.update_from_changeset, message=req)
