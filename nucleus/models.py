
import datetime
import json
import iso8601
import logging
import os
import semantic_version
import re

from base64 import b64encode, b64decode
from collections import defaultdict
from flask import url_for, current_app
from flask.ext.login import current_user, UserMixin
from hashlib import sha256
from keyczar.keys import RsaPrivateKey, RsaPublicKey
from requests.exceptions import ConnectionError, HTTPError
from soundcloud import Client as SoundcloudClient
from sqlalchemy import func, or_
from sqlalchemy.exc import SQLAlchemyError
from uuid import uuid4

from . import UPVOTE_STATES, THOUGHT_STATES, PERCEPT_STATES, ATTACHMENT_KINDS, \
    PersonaNotFoundError, UnauthorizedError, notification_signals, \
    CHANGE_TYPES, ExecutionTimer
from .helpers import process_attachments, recent_thoughts

from .jobs import refresh_recent_thoughts, refresh_conversation_lists, \
    refresh_upvote_count, check_promotion

from connections import cache, db

UPVOTE_CACHE_DURATION = 60 * 10
ATTENTION_CACHE_DURATION = 60 * 10

TOP_MOVEMENT_CACHE_DURATION = 60 * 60
MEMBER_COUNT_CACHE_DURATION = 60 * 60
REPOST_MINDSET_CACHE_DURATION = 60 * 60 * 24

TOP_THOUGHT_CACHE_DURATION = 60 * 60
RECENT_THOUGHT_CACHE_DURATION = 60 * 60 * 24
MINDSPACE_TOP_THOUGHT_CACHE_DURATION = 60 * 10

SUGGESTED_MOVEMENTS_CACHE_DURATION = 60 * 10
PERSONA_MOVEMENTS_CACHE_DURATION = 60 * 10
CONVERSATION_LIST_CACHE_DURATION = 60 * 60 * 24

IFRAME_URL_CACHE_DURATION = 24 * 60 * 60

ATTENTION_MULT = 10

request_objects = notification_signals.signal('request-objects')
movement_chat = notification_signals.signal('movement-chat')
logger = logging.getLogger('nucleus')


class Serializable():
    """ Make SQLAlchemy models json serializable

    Attributes:
        _insert_required: Default attributes to include in export
        _update_required: Default attributes to include in export with update=True
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


class User(UserMixin, db.Model):
    """A user of the website"""

    __tablename__ = 'user'

    id = db.Column(db.String(32), primary_key=True)

    active = db.Column(db.Boolean(), default=True)
    authenticated = db.Column(db.Boolean(), default=True)
    created = db.Column(db.DateTime)
    email = db.Column(db.String(128))
    modified = db.Column(db.DateTime)
    pw_hash = db.Column(db.String(64))
    validated_on = db.Column(db.DateTime)
    signup_code = db.Column(db.String(128))

    # Email preferences
    email_react_private = db.Column(db.Boolean(), default=True)
    email_react_reply = db.Column(db.Boolean(), default=True)
    email_react_mention = db.Column(db.Boolean(), default=True)
    email_react_follow = db.Column(db.Boolean(), default=False)
    email_system_security = db.Column(db.Boolean(), default=True)
    email_system_features = db.Column(db.Boolean(), default=False)
    email_catchall = db.Column(db.Boolean(), default=False)

    # Relations
    active_persona = db.relationship("Persona",
        primaryjoin="persona.c.id==user.c.active_persona_id", post_update=True,
        lazy="joined")
    active_persona_id = db.Column(db.String(32),
        db.ForeignKey('persona.id', name="fk_active_persona"))

    def __repr__(self):
        return "<User {}>".format(self.email.decode('utf-8'))

    def check_password(self, password):
        """Return True if password matches user password

        Args:
            password (String): Password entered by user in login form
        """
        pw_hash = sha256(password).hexdigest()
        return self.pw_hash == pw_hash

    def email_allowed(self, notification):
        """Return True if this user allows the notification to be sent by email

        Args:
            notification (Notification): Notification object

        Returns:
            Boolean: True if notification should be sent as email
        """
        rv = False
        if not self.email_catchall:
            if notification.email_pref:
                if getattr(self, notification.email_pref) is True:
                    c = Notification.query \
                        .filter_by(recipient=notification.recipient) \
                        .filter_by(url=notification.url) \
                        .filter_by(unread=True) \
                        .filter(Notification.id != notification.id)

                    if c.count() == 0:
                        rv = True
                    else:
                        logger.debug(
                            "{} not sent by email because {} unread notifications point to same url '{}'".format(
                                notification, c.count(), notification.url))
                else:
                    logger.debug(
                        "{} not sent by email because of '{}'".format(
                            notification, notification.email_pref))
            else:
                logger.warning(
                    "{} is missing email_pref attribute".format(notification))
        else:
            logger.debug(
                "{} not sent because of email catchall pref".format(
                    notification))
        return rv

    def get_id(self):
        return self.id

    def is_active(self):
        return self.active

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return self.authenticated

    def set_password(self, password):
        """Set password to a new value

        Args:
            password (String): Plaintext value of the new password
        """
        pw_hash = sha256(password).hexdigest()
        self.pw_hash = pw_hash

    def validate(self):
        """Set the validated_on property to the current time"""
        self.validated_on = datetime.datetime.utcnow()

    @property
    def validated(self):
        """Is True if validated_on has been set"""
        return self.validated_on is not None

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


t_identity_vesicles = db.Table(
    'identity_vesicles',
    db.Column('identity_id', db.String(32), db.ForeignKey('identity.id')),
    db.Column('vesicle_id', db.String(32), db.ForeignKey('vesicle.id'))
)


class Identity(Serializable, db.Model):
    """Abstract identity, superclass of Persona and Movement

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
        blog: Mindset containing this Identity's blog

    """

    __tablename__ = "identity"

    __mapper_args__ = {
        'polymorphic_identity': 'identity',
        'polymorphic_on': "kind"
    }

    _insert_required = ["id", "username", "crypt_public", "sign_public", "modified", "blog_id"]
    _update_required = ["id", "modified"]

    _stub = db.Column(db.Boolean, default=False)

    id = db.Column(db.String(32), primary_key=True)

    color = db.Column(db.String(6), default="B8C5D6")
    created = db.Column(db.DateTime)
    crypt_private = db.Column(db.Text)
    crypt_public = db.Column(db.Text)
    kind = db.Column(db.String(32))
    modified = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    sign_private = db.Column(db.Text)
    sign_public = db.Column(db.Text)
    username = db.Column(db.String(80))

    # Relations
    blog_id = db.Column(db.String(32), db.ForeignKey('mindset.id'))
    blog = db.relationship('Mindset', primaryjoin='mindset.c.id==identity.c.blog_id')

    mindspace_id = db.Column(db.String(32), db.ForeignKey('mindset.id'))
    mindspace = db.relationship('Mindset', primaryjoin='mindset.c.id==identity.c.mindspace_id')

    blogs_followed = db.relationship('Identity',
        secondary='blogs_followed',
        primaryjoin='blogs_followed.c.follower_id==identity.c.id',
        secondaryjoin='blogs_followed.c.followee_id==identity.c.id')

    vesicles = db.relationship(
        'Vesicle',
        secondary='identity_vesicles',
        primaryjoin='identity_vesicles.c.identity_id==identity.c.id',
        secondaryjoin='identity_vesicles.c.vesicle_id==vesicle.c.id')

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
            if not current_user.is_anonymous():
                if self.id == current_user.active_persona.id:
                    return True
                if Persona.query.get(current_user.active_persona.id).user == self.user:
                    return True
        return False

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

        # Update blog
        blog = Mindset.query.get(changeset["blog_id"])
        if blog is None or blog.get_state() == -1:
            request_list.append({
                "type": "Mindset",
                "id": changeset["blog_id"],
                "author_id": update_recipient.id if update_recipient else None,
                "recipient_id": update_sender.id if update_sender else None,
                "id": changeset["blog_id"]
            })

        if blog is None:
            blog = Blog(id=changeset["blog_id"])
            blog.state = -1

        ident.blog = blog

        logger.info("Created {} from changeset, now requesting {} linked objects".format(
            ident, len(request_list)))

        if request_sources:
            for req in request_list:
                request_objects.send(Identity.create_from_changeset, message=req)
        else:
            logger.info("Not requesting linked sources for new {}".format(kind))

        return ident

    def decrypt(self, cypher):
        """ Decrypt cyphertext using RSA """

        cypher = b64decode(cypher)
        key_private = RsaPrivateKey.Read(self.crypt_private)
        return key_private.Decrypt(cypher)

    def encrypt(self, data):
        """ Encrypt data using RSA """

        key_public = RsaPublicKey.Read(self.crypt_public)
        return b64encode(key_public.Encrypt(data))

    def generate_keys(self, password):
        """ Generate new RSA keypairs for signing and encrypting. Commit to DB afterwards! """

        # TODO: Store keys encrypted
        rsa1 = RsaPrivateKey.Generate()
        self.sign_private = str(rsa1)
        self.sign_public = str(rsa1.public_key)

        rsa2 = RsaPrivateKey.Generate()
        self.crypt_private = str(rsa2)
        self.crypt_public = str(rsa2.public_key)

    def notification_list(self, limit=5):
        return self.notifications \
            .filter_by(unread=True) \
            .order_by(Notification.modified.desc()) \
            .limit(limit) \
            .all()

    def sign(self, data):
        """ Sign data using RSA """

        key_private = RsaPrivateKey.Read(self.sign_private)
        signature = key_private.Sign(data)
        return b64encode(signature)

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

        # Update blog
        if "blog_id" in changeset:
            blog = Mindset.query.get(changeset["blog_id"])
            if blog is None or blog.get_state() == -1:
                request_list.append({
                    "type": "Mindset",
                    "id": changeset["blog_id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })
                logger.info("Requested {}'s {}".format(self.username, "blog mindset"))
            else:
                self.blog = blog
                logger.info("Updated {}'s {}".format(self.username, "blog mindset"))

        logger.info("Updated {} identity from changeset. Requesting {} objects.".format(self, len(request_list)))

        for req in request_list:
            request_objects.send(Identity.create_from_changeset, message=req)

    def verify(self, data, signature_b64):
        """ Verify a signature using RSA """

        signature = b64decode(signature_b64)
        key_public = RsaPublicKey.Read(self.sign_public)
        return key_public.Verify(data, signature)

#
# Setup follower relationship on Persona objects
#

t_contacts = db.Table('contacts',
    db.Column('left_id', db.String(32), db.ForeignKey('persona.id')),
    db.Column('right_id', db.String(32), db.ForeignKey('persona.id')),
    db.UniqueConstraint('left_id', 'right_id', name='_uc_contacts')
)

t_blogs_followed = db.Table('blogs_followed',
    db.Column('follower_id', db.String(32), db.ForeignKey('identity.id')),
    db.Column('followee_id', db.String(32), db.ForeignKey('identity.id'))
)


class Persona(Identity):
    """A Persona represents a user profile

    Attributes:
        email: An email address, max 120 bytes
        contacts: List of this Persona's contacts
        index: Mindset containing all Thought's this Persona publishes to its contacts
        myelin_offset: Datetime of last request for Vesicles sent to this Persona

    """
    __mapper_args__ = {
        'polymorphic_identity': 'persona'
    }

    _insert_required = Identity._insert_required + ["email", "index_id", "contacts", "movements"]
    _update_required = Identity._update_required

    id = db.Column(db.String(32), db.ForeignKey('identity.id'), primary_key=True)

    auth = db.Column(db.String(32))
    last_connected = db.Column(db.DateTime, default=datetime.datetime.now())
    # Myelin offset stores the date at which the last Vesicle receieved from Myelin was created
    myelin_offset = db.Column(db.DateTime)
    email = db.Column(db.String(120))
    session_id = db.Column(db.String(32))

    # Relations
    contacts = db.relationship('Persona',
        secondary='contacts',
        lazy="dynamic",
        remote_side='contacts.c.right_id',
        primaryjoin='contacts.c.left_id==persona.c.id',
        secondaryjoin='contacts.c.right_id==persona.c.id')

    index_id = db.Column(db.String(32), db.ForeignKey('mindset.id'))
    index = db.relationship('Mindset',
        primaryjoin='mindset.c.id==persona.c.index_id')

    user_id = db.Column(db.String(32),
        db.ForeignKey('user.id', use_alter=True, name="fk_persona_user"))
    user = db.relationship('User',
        backref="associations", primaryjoin="user.c.id==persona.c.user_id")

    def __repr__(self):
        try:
            name = self.username.encode('utf-8')
        except AttributeError:
            name = ""
        return "<Persona @{} [{}]>".format(name, self.id[:6])

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

    @cache.memoize(timeout=ATTENTION_CACHE_DURATION)
    def get_attention(self):
        """Return a numberic value indicating attention this Persona has received

        Returns:
            integer: Attention as a positive integer
        """
        timer = ExecutionTimer()
        thoughts = Thought.query \
            .filter_by(author=self)

        rv = int(sum([t.hot() for t in thoughts]) * ATTENTION_MULT)
        timer.stop("Generated attention value for {}".format(self))
        return rv

    attention = property(get_attention)

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """See Serializable.create_from_changeset"""
        p = Identity.create_from_changeset(changeset,
            stub=stub, update_sender=update_sender, update_recipient=update_recipient, kind=Persona)

        request_list = list()

        p.email = changeset["email"]

        # Update index
        index = Mindset.query.get(changeset["index_id"])
        if index is None or index.get_state() == -1:
            request_list.append({
                "type": "Mindset",
                "id": changeset["index_id"],
                "author_id": update_recipient.id,
                "recipient_id": update_sender.id,
            })

        if index is None:
            index = Mindset(id=changeset["index_id"])
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

        # Request unknown movements
        movements_to_check = set(changeset["movements"] + changeset["blogs_followed"])
        for movement_info in movements_to_check:
            movement = Movement.query.get(movement_info["id"])
            if movement is None:
                request_list.append({
                    "type": "Movement",
                    "id": movement_info["id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })

        logger.info("Made {} a Persona object, now requesting {} linked objects".format(
            p, len(request_list)))

        for req in request_list:
            request_objects.send(Persona.create_from_changeset, message=req)

        return p

    @cache.memoize(timeout=CONVERSATION_LIST_CACHE_DURATION)
    def conversation_list(self):
        """Return a list of conversations this persona had

        Returns:
            list: List of dicts with keys
                persona_id: id of the other side of the conversation
                persona_username: respective username
                modified: last thought in the conversation
        """
        timer = ExecutionTimer()
        convs_query = Dialogue.query \
            .filter(or_(
                Dialogue.author == self,
                Dialogue.other == self
            )).all()

        convs = list()
        for c in convs_query:
            last_post = c.index.order_by(Thought.created.desc()).first()
            if last_post:
                other = c.other if c.author == self else c.author
                conv_dict = dict(
                    persona_id=other.id,
                    persona_username=other.username,
                    modified=last_post.created)
                convs.append(conv_dict)
        convs = sorted(convs, reverse=True, key=lambda c: c["modified"]
            if c["modified"] else datetime.datetime.utcfromtimestamp(0))
        timer.stop("Generated conversation list for {}".format(self))
        return convs

    def export(self, exclude=[], include=None, update=False):
        exclude = set(exclude + ["contacts", "movements", "blogs_followed"])
        data = Identity.export(self, exclude=exclude, include=include, update=update)

        data["contacts"] = list()
        for contact in self.contacts:
            data["contacts"].append({
                "id": contact.id,
            })

        data["movements"] = list()
        for movement in self.movements:
            data["movements"].append({
                "id": movement.id,
            })

        data["blogs_followed"] = list()
        for ident in self.blogs_followed:
            data["blogs_followed"].append({
                "id": ident.id
            })

        return data

    @cache.memoize(timeout=TOP_THOUGHT_CACHE_DURATION)
    def frontpage_sources(self):
        """Return mindset IDs that provide posts for this Persona's frontpage

        Returns:
            list: List of IDs
        """
        source_idents = set()
        for source in self.blogs_followed:
            if isinstance(source, Movement) and source.active_member():
                source_idents.add(source.mindspace_id)
            source_idents.add(source.blog_id)

        return source_idents

    def get_absolute_url(self):
        return url_for('web.persona', id=self.id)

    def get_email_hash(self):
        """Return sha256 hash of this user's email address"""
        return sha256(self.email).hexdigest()

    @cache.memoize(timeout=PERSONA_MOVEMENTS_CACHE_DURATION)
    def movements(self):
        """Return movements in which this Persona is an active member

        Returns:
            list: List of dicts with keys 'id', 'username' for each movement
        """
        timer = ExecutionTimer()
        user_movements = Movement.query \
            .join(MovementMemberAssociation) \
            .filter(MovementMemberAssociation.active == True) \
            .filter(MovementMemberAssociation.persona
                 == current_user.active_persona) \
            .order_by(Movement.username)

        rv = [dict(id=m.id, username=m.username)
            for m in user_movements]
        timer.stop("Generated movement list for {}".format(self))
        return rv

    @cache.memoize(timeout=REPOST_MINDSET_CACHE_DURATION)
    def repost_mindsets(self):
        """Return list of mindset IDs in which this persona might post

        Returns:
            list: mindset IDs
        """

        rv = []
        rv.append(self.mindspace)
        rv.append(self.blog)

        # Is a movement member
        rv = rv + Mindset.query \
            .join(Movement, Movement.mindspace_id == Mindset.id) \
            .filter(Movement.id.in_([m["id"] for m in self.movements()])).all()
        return [ms.id for ms in rv]

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

    def reset(self):
        """Reset session_id"""
        self.session_id = uuid4().hex
        self.auth = uuid4().hex
        return self.session_id

    @cache.memoize(timeout=SUGGESTED_MOVEMENTS_CACHE_DURATION)
    def suggested_movements(self):
        """Return a list of IDs for movements that are not followed but have
        many members.

        Returns:
            list: IDs of Movements
        """
        timer = ExecutionTimer()
        mov_selection = Movement.top_movements()
        user_movs = [mma.movement.id for mma in self.movement_assocs]
        rv = [m['id'] for m in mov_selection if m['id'] not in user_movs]
        timer.stop("Generated suggested movements for {}".format(self))
        return rv

    def timeout(self):
        return self.last_connected + current_app.config['SESSION_EXPIRATION_TIME']

    def toggle_following(self, ident):
        """Toggle whether this Persona is following a blog.

        Args:
            ident (Identity): Whose blog to follow/unfollow

        Returns:
            boolean -- True if the blog is now being followed, False if not
        """
        following = False

        try:
            self.blogs_followed.remove(ident)
            logger.info("{} is not following {} anymore".format(self, ident))
        except ValueError:
            self.blogs_followed.append(ident)
            following = True
            logger.info("{} is now following {}".format(self, ident))

        cache.delete_memoized(self.frontpage_sources)
        return following

    def toggle_movement_membership(self, movement, role="member",
            invitation_code=None):
        """Toggle whether this Persona is member of a movement.

        Also enables movement following for this Persona/Movement.

        Args:
            movement (Movement): Movement entity to be become member of
            role (String): What role to take in the movement. May be "member"
                or "admin"
            invitation_code (String): (Optional) If the movement is private
                an invitation code may be needed to join

        Returns:
            Updated MovementMemberAssociation object
        """
        if invitation_code and len(invitation_code) > 0:
            mma = MovementMemberAssociation.query \
                .filter_by(invitation_code=invitation_code) \
                .first()
        else:
            mma = MovementMemberAssociation.query \
                .filter_by(movement=movement) \
                .filter_by(persona=self) \
                .first()

        # Follow movement when joining
        if movement not in self.blogs_followed and (mma is None or not mma.active):
            logger.info("Setting {} to follow {}.".format(self, movement))
            self.toggle_following(movement)

        # Validate invitation code
        if mma is None or (mma.active is False and mma.invitation_code != invitation_code):
            if movement.private and current_user.active_persona != movement.admin:
                logger.warning("Invalid invitation code '{}'".format(invitation_code))
                raise UnauthorizedError("Invalid invitation code '{}'".format(invitation_code))

        if mma is None:
            logger.info("Enabling membership of {} in {}".format(self, movement))
            mma = MovementMemberAssociation(
                persona=self,
                movement=movement,
                role=role,
            )

        elif mma.active is False:
            mma.active = True
            mma.role = role
            logger.info("Membership of {} in {} re-enabled".format(self, movement))

        else:
            if self.id == movement.admin_id:
                raise NotImplementedError("Admin can't leave the movement")
            logger.info("Disabling membership of {} in {}".format(self, movement))
            mma.active = False
            mma.role = "left"

        # Reset caches
        cache.delete_memoized(movement.member_count)
        cache.delete_memoized(self.movements)
        cache.delete_memoized(self.repost_mindsets)
        cache.delete_memoized(self.frontpage_sources)

        return mma

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
            index = Mindset.query.get(changeset["index_id"])
            if index is None or index.get_state() == -1:
                request_list.append({
                    "type": "Mindset",
                    "id": changeset["index_id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })
                logger.info("Requested {}'s new {}".format(self.username, "index mindset"))
            else:
                self.index = index
                logger.info("Updated {}'s {}".format(self.username, "index mindset"))

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

        # Request unknown movements
        movements_1 = changeset.get('movements') or []
        movements_2 = changeset.get('blogs_followed') or []
        movements_to_check = movements_1 + movements_2

        # TODO This doesn't work anymore because Movement is inheriting from Identity
        for movement_info in movements_to_check:
            movement = Identity.query.get(movement_info["id"])
            if movement is None:
                request_list.append({
                    "type": "Movement",
                    "id": movement_info["id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })

        logger.info("Updated {} from changeset. Requesting {} objects.".format(self, len(request_list)))

        for req in request_list:
            request_objects.send(Persona.update_from_changeset, message=req)


class Notification(db.Model):
    """Notification model

    Attributes:
        id: Integer identifier
        text: The text displayed in the notifications
        url: The URL clicking the notification will take the user
        source: The source of the notification
        domain: Domain of the notification, used for grouping
        unread: Whether the notification has been read by the user
        created: When the notifcation was generated
        modfied: When some part of the notification was last changed
        recipient: The Identity for whom this notifcation is intended
    """

    __tablename__ = "notification"

    __mapper_args__ = {
        'polymorphic_identity': 'notification',
        'polymorphic_on': 'domain'
    }

    id = db.Column(db.Integer, primary_key=True)

    created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    domain = db.Column(db.String(128))
    modified = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    source = db.Column(db.String(128))
    text = db.Column(db.Text)
    unread = db.Column(db.Boolean(), default=True)
    url = db.Column(db.Text, default="/")

    # Set this to the name of the attribute on User model (that is, the email
    # preference) that determines whether the notification sends emails
    email_pref = None

    # Relations
    recipient = db.relationship('Identity',
        backref=db.backref('notifications', lazy="dynamic"))
    recipient_id = db.Column(db.String(32), db.ForeignKey('identity.id'))

    def __repr__(self):
        return "<Notification '{}'>".format(self.text)


class MentionNotification(Notification):
    __mapper_args__ = {
        'polymorphic_identity': 'mention_notification',
    }
    email_pref = "email_react_mention"

    def __init__(self, mention, author, url):
        super(MentionNotification, self).__init__()
        self.text = "{} mentioned you in a Thought".format(author.username)
        self.url = url
        self.source = author.username
        self.recipient = mention.identity


class ReplyNotification(Notification):
    __mapper_args__ = {
        'polymorphic_identity': 'reply_notification'
    }
    email_pref = "email_react_reply"

    def __init__(self, parent_thought, author, url):
        super(ReplyNotification, self).__init__()
        self.text = "{} replied to your Thought".format(author.username)
        self.url = url
        self.source = author.username
        self.recipient = parent_thought.author


class DialogueNotification(Notification):
    __mapper_args__ = {
        'polymorphic_identity': 'dialogue_notification'
    }
    email_pref = "email_react_private"

    def __init__(self, author, recipient):
        super(DialogueNotification, self).__init__()
        self.text = "{} sent you a private message".format(author.username)
        self.url = url_for("web.persona", id=author.id)
        self.source = author.username
        self.recipient = recipient


class FollowerNotification(Notification):
    __mapper_args__ = {
        'polymorphic_identity': 'follower_notification'
    }
    email_pref = "email_react_follow"

    def __init__(self, author, recipient):
        super(FollowerNotification, self).__init__()
        self.text = "{} is now following your blog".format(author.username)
        self.url = author.get_absolute_url()
        self.recipient = recipient
        self.source = author.username


t_thought_vesicles = db.Table(
    'thought_vesicles',
    db.Column('thought_id', db.String(32), db.ForeignKey('thought.id')),
    db.Column('vesicle_id', db.String(32), db.ForeignKey('vesicle.id'))
)


class Thought(Serializable, db.Model):
    """A Thought represents a post"""

    __tablename__ = "thought"

    __mapper_args__ = {
        'polymorphic_identity': 'thought',
        'polymorphic_on': 'kind'
    }

    _insert_required = ["id", "text", "created", "modified", "author_id",
        "percept_assocs", "parent_id", "mindset_id"]
    _update_required = ["id", "text", "modified"]

    id = db.Column(db.String(32), primary_key=True)
    context_length = db.Column(db.Integer, default=3)
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    kind = db.Column(db.String(32))
    modified = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    state = db.Column(db.Integer, default=0)
    text = db.Column(db.Text)
    posted_from = db.Column(db.String(64))

    _comment_count = db.Column(db.Integer)
    _upvotes = db.Column(db.Integer)
    _blogged = db.Column(db.Boolean, default=False)

    # Relations
    author = db.relationship('Identity',
        backref=db.backref('thoughts'),
        primaryjoin="identity.c.id==thought.c.author_id", lazy="joined")
    author_id = db.Column(db.String(32), db.ForeignKey('identity.id'))

    mindset = db.relationship('Mindset',
        primaryjoin='mindset.c.id==thought.c.mindset_id',
        backref=db.backref('index', lazy="dynamic"))
    mindset_id = db.Column(db.String(32), db.ForeignKey('mindset.id'))

    parent = db.relationship('Thought',
        primaryjoin='and_(remote(Thought.id)==Thought.parent_id, Thought.state>=0)',
        backref=db.backref('children', lazy="joined"),
        remote_side='Thought.id')
    parent_id = db.Column(db.String(32), db.ForeignKey('thought.id'))

    percept_assocs = db.relationship("PerceptAssociation",
        backref="thought",
        lazy="joined")

    vesicles = db.relationship('Vesicle',
        secondary='thought_vesicles',
        primaryjoin='thought_vesicles.c.thought_id==thought.c.id',
        secondaryjoin='thought_vesicles.c.vesicle_id==vesicle.c.id')

    def __repr__(self):
        return "<Thought {}>".format(self.id[:8])

    def authorize(self, action, author_id=None):
        """Return True if this Thought authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        rv = False

        if Serializable.authorize(self, action, author_id=author_id):
            # Thoughts may be read by anyone who may see their mindset/parent
            if action == "read":
                if self.mindset is not None:
                    rv = self.mindset.authorize("read", author_id)
                else:
                    rv = self.parent.authorize("read", author_id)

            # Other actions are allowed for the Thought author
            # and administrators of its mindset context
            elif action == "delete":
                if author_id == self.author.id:
                    rv = True
                elif self.mindset:
                    rv = self.mindset.authorize(action, author_id)
            else:
                if author_id == self.author.id:
                    rv = True
                elif isinstance(self.author, Movement) \
                        and author_id == self.author.admin.id:
                    rv = True
        return rv

    def get_attachments(self):
        rv = defaultdict(list)
        for pa in self.percept_assocs:
            if pa.percept.kind in ATTACHMENT_KINDS:
                rv[pa.percept.kind].append(pa)

        return rv

    attachments = property(get_attachments)

    @classmethod
    def clone(cls, thought, author, mindset):
        """Return a deep copy of the given Thought

        Args:
            thought (Thought): The Thought object to be copied
            author (Persona): Author of the new Thought
            mindset (Mindset): Where to put the new thought

        Returns:
            Thought: The new copy
        """
        thought_id = uuid4().hex
        thought_cloned = datetime.datetime.utcnow()

        new_thought = cls(
            id=thought_id,
            text=thought.text,
            author=author,
            parent=thought,
            created=thought_cloned,
            modified=thought_cloned,
            mindset=mindset)

        for pa in thought.percept_assocs:
            assoc = PerceptAssociation(
                thought=new_thought, percept=pa.percept, author=author)
            new_thought.percept_assocs.append(assoc)

        return new_thought

    def comment_count(self, iter=15):
        """
        Return the number of comments this Thought has receieved

        Iterates up to a depth of 15 replies of self._comment_count is None

        Returns:
            Int: Number of comments
        """
        if self._comment_count is None:
            rv = 0
            iter = iter - 1
            if iter > 0:
                for comment in self.comments:
                    if comment.state == 0:
                        rv += comment.comment_count(iter=iter) + 1
            self._comment_count = rv
        return self._comment_count

    def get_comments(self):
        return [thought for thought in self.children if thought.kind == "thought"]

    comments = property(get_comments)

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """See Serializable.create_from_changeset"""
        created_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)

        if stub is not None:
            thought = stub
            thought.text = changeset["text"]
            thought.author = None
            thought.created = created_dt
            thought.modified = modified_dt
            thought.mindset_id = changeset["mindset_id"]
        else:
            thought = Thought(
                id=changeset["id"],
                text=changeset["text"],
                author=None,
                created=created_dt,
                modified=modified_dt,
                mindset_id=changeset["mindset_id"]
            )

        author = Persona.query.get(changeset["author_id"])
        if author is None:
            # TODO: Send request for author
            thought.author_id = changeset["author_id"]
        else:
            thought.author = author

        # Append percepts to new Thought
        for percept_assoc in changeset["percept_assocs"]:
            if not PerceptAssociation.validate_changeset(percept_assoc):
                logger.warning("Invalid changeset for percept associated with {}\n\n{}".format(thought, changeset))
            else:
                author = Persona.request_persona(percept_assoc["author_id"])
                pid = percept_assoc["percept"]["id"]

                # TODO: Better lookup method for percept classes
                if percept_assoc["percept"]["kind"] == "link":
                    percept_cls = LinkPercept
                elif percept_assoc["percept"]["kind"] == "linkedpicture":
                    percept_cls = LinkedPicturePercept
                elif percept_assoc["percept"]["kind"] == "text":
                    percept_cls = TextPercept
                else:
                    raise NotImplementedError("Percept class {} is not implemented yet".format(
                        percept_assoc["percept"]["kind"]))

                percept = percept_cls.query.get(pid)
                if percept is None:
                    percept = percept_cls.create_from_changeset(percept_assoc["percept"])
                else:
                    percept.update_from_changeset(percept_assoc["percept"])

                assoc = PerceptAssociation(author=author, percept=percept)
                thought.percept_assocs.append(assoc)
                logger.info("Added {} to new {}".format(percept, thought))

        logger.info("Created {} from changeset".format(thought))

        if changeset["parent_id"] != "None":
            parent = Thought.query.get(changeset["parent_id"])
            if parent:
                thought.parent = parent
            else:
                logger.info("Requesting {}'s parent thought".format(thought))
                request_objects.send(Thought.create_from_changeset, message={
                    "type": "Thought",
                    "id": changeset["parent_id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })

        return thought

    @classmethod
    def create_from_input(cls, text, author=None, longform=None,
            longform_source=None, mindset=None, parent=None,
            extract_percepts=True):
        """Create a new Thought object from user input

        Args:
            text (String): Title text of the thought
            author (Persona): Author of the Thought. If None, this is set to
                the currently active persona
            longform (String): Extended text of the Thought
            mindset (Mindset): Optional context in which the Thought will be placed
            parent (Thought): Optional parent to which this is a reply
            extract_percepts (Booleand): Option for extracting percepts from
                longform parameter

        Returns:
            dict: with keys
                instance: The new Thought object
                notifications: List of notification objects resulting from
                    posting this Thought

        Raises:
            ValueError: For illegal parameter values or combinations thereof

        """
        thought_created = datetime.datetime.utcnow()
        thought_id = uuid4().hex
        notifications = list()
        percepts = set()

        if author is None:
            if current_user.is_anonymous():
                raise ValueError("Thought author can't be anonymous ({}).".format(
                    author))
            logger.debug("Set new thought author to active persona")
            author = current_user.active_persona

        if mindset is not None and isinstance(mindset, Dialogue):
            recipient = mindset.author if mindset.author is not author \
                else mindset.other
            notifications.append(DialogueNotification(
                author=author, recipient=recipient))

        instance = cls(
            id=thought_id,
            text=text,
            author=author,
            parent=parent,
            created=thought_created,
            modified=thought_created,
            mindset=mindset,
            _upvotes=0)

        if extract_percepts:
            text, percepts = process_attachments(instance.text)
            instance.text = text
            logger.debug("Extracted {} percepts from title".format(len(percepts)))

            if longform and len(longform) > 0:
                lftext, lfpercepts = process_attachments(longform)
                percepts = percepts.union(lfpercepts)
                logger.debug("Extracted {} percepts from longform".format(len(percepts)))

                lftext_percept = TextPercept.get_or_create(lftext,
                    source=longform_source)
                percepts.add(lftext_percept)
                logger.debug("Attached longform content")

            for percept in percepts:
                if isinstance(percept, Mention):
                    notifications.append(MentionNotification(percept,
                        author, url_for('web.thought', id=thought_id)))

                assoc = PerceptAssociation(
                    thought=instance, percept=percept, author=author)
                instance.percept_assocs.append(assoc)
                logger.debug("Attached {} to new {}".format(percept, instance))

        if parent is not None:
            parent.update_comment_count(1)

        if parent is not None and parent.author != author:
            notifications.append(ReplyNotification(parent_thought=parent,
                author=author, url=url_for('web.thought', id=thought_id)))

        refresh_recent_thoughts.delay()
        if instance.mindset and isinstance(instance.mindset, Dialogue):
            refresh_conversation_lists.delay(instance.mindset.id)

        return {
            "instance": instance,
            "notifications": notifications
        }

    def export(self, exclude=[], include=None, update=False):
        """See Serializable.export"""

        ex = set(exclude + ["percepts", ])
        data = Serializable.export(self, exclude=ex, include=include, update=update)

        data["percept_assocs"] = list()
        for percept_assoc in self.percept_assocs:
            data["percept_assocs"].append({
                "percept": percept_assoc.percept.export(),
                "author_id": percept_assoc.author_id
            })

        return data

    def get_absolute_url(self):
        return url_for('web.thought', id=self.id)

    def get_state(self):
        """
        Return publishing state of this thought.

        Returns:
            Integer:
                -2 -- deleted
                -1 -- unavailable
                0 -- published
                1 -- draft
                2 -- private
                3 -- updating
        """
        return THOUGHT_STATES[self.state][0]
        return None

    def has_text(self):
        """Return True if this Thought has a TextPercept"""
        try:
            first = self.text_percepts()[0]
        except IndexError:
            first = None

        return first is not None

    def hot(self):
        from math import pow
        s = self.upvote_count()
        t = (datetime.datetime.utcnow() - self.created).total_seconds() / 3600 + 2
        rv = (s / pow(t, 1.5))
        return rv

    def update_comment_count(self, incr):
        """Increment comment count by one on this thought and recurse parents"""
        if not isinstance(incr, int):
            raise ValueError("Can only change comment count by integer values. Got {}: {}".format(type(incr), incr))

        self._comment_count = self.comment_count() + incr
        if self.parent is not None:
            self.parent.update_comment_count(incr)

    def link_url(self):
        """Return URL if this Thought has a Link-Percept

        Returns:
            String: URL of the first associated Link
            Bool: False if no link was found
        """
        # percept_assoc = self.percept_assocs.join(PerceptAssociation.percept.of_type(LinkPercept)).first()

        for percept_assoc in self.percept_assocs:
            if percept_assoc.percept.kind == "link":
                return percept_assoc.percept.url

    def set_state(self, new_state):
        """
        Set the publishing state of this thought

        Parameters:
            new_state (int) code of the new state as defined in nucleus.THOUGHT_STATES

        Raises:
            ValueError: If new_state is not an Int or not a valid state of this object
        """
        new_state = int(new_state)
        if new_state not in THOUGHT_STATES.keys():
            raise ValueError("{} ({}) is not a valid thought state").format(
                new_state, type(new_state))
        else:
            cache.delete_memoized(recent_thoughts)
            self.state = new_state

    def get_tags(self):
        return self.percept_assocs.join(Percept).filter(Percept.kind == "tag")

    tags = property(get_tags)

    @classmethod
    @cache.memoize(timeout=TOP_THOUGHT_CACHE_DURATION)
    def top_thought(cls, source=None, min_votes=0, filter_blogged=False):
        """Return up to 10 hottest thoughts as measured by Thought.hot

        Args:
            source (String): "blog" or "mindspace" to count only thoughts from
                those sources
            source (set): Set of Mindset IDs to get content from
            filter_blogged (Boolean): Don't include Thought if Thought.blogged
                is True

        Returns:
            list: List of thought ids
        """
        timer = ExecutionTimer()
        top_post_selection = cls.query.filter(cls.state >= 0)

        if filter_blogged:
            top_post_selection = top_post_selection.filter_by(_blogged=False)

        if source == "blog":
            top_post_selection = top_post_selection \
                .join(Mindset) \
                .filter(Mindset.kind == "blog")

        elif source == "mindspace":
            top_post_selection = top_post_selection \
                .join(Mindset) \
                .filter(Mindset.kind == "mindspace")

        elif isinstance(source, set):
            top_post_selection = top_post_selection.filter(
                Thought.mindset_id.in_(list(source)))

        top_post_selection = sorted(top_post_selection, key=cls.hot, reverse=True)

        rv = list()
        while len(rv) < min([10, len(top_post_selection)]):
            candidate = top_post_selection.pop(0)
            # Don't return blogged thoughts for source "mindspace"
            if source != "mindspace" or not candidate._blogged:
                if min_votes > 0:
                    if candidate.upvote_count() >= min_votes:
                        rv.append(candidate.id)
                else:
                    rv.append(candidate.id)
        timer.stop("Generated top thought from {}s".format(
            source if isinstance(source, str) else "movement list"))
        return rv

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a Thought from a changeset (See Serializable.update_from_changeset)"""
        # Update modified
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        self.modified = modified_dt

        # Update text
        self.text = changeset["text"]

        for percept_assoc in changeset["percept_assocs"]:
            if not PerceptAssociation.validate_changeset(percept_assoc):
                logger.warning("Invalid changeset for percept associated with {}\n{}".format(self, changeset))
            else:
                author = Persona.request_persona(percept_assoc["author_id"])
                pid = percept_assoc["percept"]["id"]

                assoc = PerceptAssociation.filter_by(thought_id=self.id).filter_by(percept_id=pid).first()
                if assoc is None:
                    percept = Percept.query.get(pid)
                    if percept is None:
                        percept = Percept.create_from_changeset(percept_assoc["percept"])
                    else:
                        percept.update_from_changeset(percept_assoc["percept"])

                    assoc = PerceptAssociation(author=author, percept=percept)
                    self.percept_assocs.append(assoc)
                    logger.info("Added {} to {}".format(percept, self))

        logger.info("Updated {} from changeset".format(self))

    def upvoted(self):
        """
        Return True if active Persona has Upvoted this Thought
        """
        if current_user.is_anonymous():
            return False

        upvote = self.upvotes.filter_by(author=current_user.active_persona).first()

        if upvote is None or upvote.state < 0:
            return False
        else:
            return True

    def get_upvotes(self):
        """Returns a query for all upvotes, including disabled ones"""
        # return self.children.filter_by(kind="upvote")
        return Thought.query.filter_by(kind="upvote").filter_by(parent_id=self.id)

    upvotes = property(get_upvotes)

    @cache.memoize(timeout=UPVOTE_CACHE_DURATION)
    def upvote_count(self):
        """
        Return the number of verified upvotes this Thought has receieved

        Returns:
            Int: Number of upvotes
        """
        rv = self._upvotes

        if rv is None:
            self._upvotes = self.upvotes.filter(Upvote.state >= 0).count()
            rv = self._upvotes
            db.session.add(self)
            try:
                db.session.commit()
            except SQLAlchemyError:
                logger.exception("Error initial upvote count")
                db.session.rollback()
        return rv

    def text_percepts(self):
        """Return TextPercepts of this Thought"""
        return self.percept_assocs.join(PerceptAssociation.percept.of_type(TextPercept)).all()

    def toggle_upvote(self, author_id=None):
        """
        Toggle Upvote for this Thought on/off

        Args:
            author_id (String): Optional Persona ID that issued the Upvote. Defaults to active Persona.

        Returns:
            Upvote: The toggled upvote object

        Raises:
            PersonaNotFoundError: Upvote author not found
            UnauthorizedError: Author is a foreign Persona
        """

        if author_id is None:
            if current_user.is_anonymous():
                return PersonaNotFoundError("You need to log in for voting")

            author = current_user.active_persona
        else:
            author = Persona.query.get(author_id)

        if author is None:
            raise PersonaNotFoundError("Upvote author not found")

        if not author.controlled():
            raise UnauthorizedError("Can't toggle Upvotes with foreign Persona {}".format(author))

        # Check whether Upvote has been previously issued
        upvote = self.upvotes.filter_by(author=author).first()
        if upvote is not None:
            if upvote.state == 0:
                upvote.set_state(-1)
                self._upvotes -= 1
                logger.info("Disabling upvote by {} on {}".format(author, self))
            else:
                upvote.set_state(0)
                self._upvotes += 1
                logger.info("Enabling upvote by {} on {}".format(author, self))
        else:
            upvote = Upvote(id=uuid4().hex, author=author, parent=self, state=0)
            self.children.append(upvote)
            self._upvotes += 1
            logger.info("Adding upvote by {} on {}".format(author, self))

        # Commit Upvote
        db.session.add(self)
        try:
            db.session.commit()
        except SQLAlchemyError:
            logger.exception("Error toggling upvote")
        else:
            refresh_upvote_count.delay(self)

            if upvote.state == 0 and \
                isinstance(self.mindset, Mindspace) and \
                    isinstance(self.mindset.author, Movement):

                check_promotion.delay(self)
            return upvote


class PerceptAssociation(db.Model):
    """Associates Percepts with Thoughts, defining an author for the connection"""

    __tablename__ = 'percept_association'

    percept_id = db.Column(db.String(32), db.ForeignKey('percept.id'), primary_key=True)
    thought_id = db.Column(db.String(32), db.ForeignKey('thought.id'), primary_key=True)

    author_id = db.Column(db.String(32), db.ForeignKey('identity.id'))
    author = db.relationship("Identity", backref="percept_assocs", lazy="joined")
    percept = db.relationship("Percept", backref="thought_assocs", lazy="joined")

    @classmethod
    def validate_changeset(cls, changeset):
        """Return True if `changeset` is a valid PerceptAssociation changeset"""

        if "author_id" not in changeset or changeset["author_id"] is None:
            logger.warning("Missing `author_id` in changeset")
            return False

        if "percept" not in changeset or changeset["percept"] is None or "kind" not in changeset["percept"]:
            logger.warning("Missing `percept` or `percept.kind` in changeset")
            return False

        p_cls = LinkPercept if changeset["percept"]["kind"] == "link" else LinkedPicturePercept
        return p_cls.validate_changeset(changeset)


t_percept_vesicles = db.Table(
    'percept_vesicles',
    db.Column('percept_id', db.String(32), db.ForeignKey('percept.id')),
    db.Column('vesicle_id', db.String(32), db.ForeignKey('vesicle.id'))
)


class Percept(Serializable, db.Model):
    """A Percept represents an attachment"""

    __tablename__ = 'percept'

    __mapper_args__ = {
        'polymorphic_identity': 'percept',
        'polymorphic_on': "kind"
    }

    _insert_required = ["id", "title", "created", "modified", "source", "kind"]
    _update_required = ["id", "title", "modified", "source"]

    id = db.Column(db.String(32), primary_key=True)

    created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    kind = db.Column(db.String(32))
    modified = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    source = db.Column(db.String(128))
    state = db.Column(db.Integer, default=0)
    title = db.Column(db.Text)

    # Relations
    vesicles = db.relationship(
        'Vesicle',
        secondary='percept_vesicles',
        primaryjoin='percept_vesicles.c.percept_id==percept.c.id',
        secondaryjoin='percept_vesicles.c.vesicle_id==vesicle.c.id')

    def __repr__(self):
        return "<Percept:{} [{}]>".format(self.kind, self.id[:6])

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Percept object from a changeset (See Serializable.create_from_changeset). """
        created_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)

        if stub is not None:
            if not isinstance(stub, Percept):
                raise ValueError("Invalid stub of type {}".format(type(stub)))

            new_percept = stub
            new_percept.id = changeset["id"]
            new_percept.title = changeset["title"]
            new_percept.source = changeset["source"]
            new_percept.created = created_dt
            new_percept.modified = modified_dt
        else:
            new_percept = Percept(
                id=changeset["id"],
                title=changeset["title"],
                created=created_dt,
                modified=modified_dt,
                source=changeset["source"]
            )

        logger.info("Created new {} from changeset".format(new_percept))
        return new_percept

    def get_state(self):
        """
        Return publishing state of this percept.

        Returns:
            Integer:
                -2 -- deleted
                -1 -- unavailable
                0 -- published
                1 -- draft
                2 -- private
                3 -- updating
        """
        return PERCEPT_STATES[self.state][0]

    def set_state(self, new_state):
        """
        Set the publishing state of this percept

        Parameters:
            new_state (int) code of the new state as defined in nucleus.PERCEPT_STATES

        Raises:
            ValueError: If new_state is not an Int or not a valid state of this object
        """
        new_state = int(new_state)
        if new_state not in PERCEPT_STATES.keys():
            raise ValueError("{} ({}) is not a valid percept state").format(
                new_state, type(new_state))
        else:
            self.state = new_state

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a new Percept object from a changeset (See Serializable.update_from_changeset). """
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)

        self.title = changeset["title"]
        self.source = changeset["source"]
        self.modifed = modified_dt

        return self


class Tag(Serializable, db.Model):
    __tablename__ = "tag"

    id = db.Column(db.String(32), primary_key=True)

    name = db.Column(db.String(32))

    @classmethod
    def get_or_create(cls, name, *args, **kwargs):
        if name is None:
            raise ValueError("Must give a name")

        inst = cls.query.filter_by(name=name).first()
        if inst is None:
            inst = cls.query.join(TagPercept).filter(TagPercept.title == name).first()
            if inst is None:
                inst = cls(name=name, *args, **kwargs)
                inst.id = uuid4().hex

        return inst


class TagPercept(Percept):
    """A Tag"""

    _insert_required = ["id", "title", "created", "modified", "kind", "tag"]
    _update_required = ["id", "modified"]

    id = db.Column(db.String(32), db.ForeignKey('percept.id'), primary_key=True)

    # Relations
    tag_id = db.Column(db.String(32), db.ForeignKey('tag.id'))
    tag = db.relationship('Tag', backref="synonyms")

    def __init__(self, *args, **kwargs):
        Percept.__init__(self, *args, **kwargs)
        self.id = uuid4().hex
        self.tag = Tag.get_or_create(kwargs["title"])

    def __repr__(self):
        return "<#{} (#{}) [{}]>".format(self.title, self.tag.name, self.id[:6])

    @staticmethod
    def create_from_changeset(changeset, update_sender=None, update_recipient=None):
        stub = TagPercept()
        new_percept = Percept.create_from_changeset(changeset, stub=stub,
            update_sender=update_sender, update_recipient=update_recipient)

        new_percept.tag = Tag.get_or_create(changeset["tag"])
        return new_percept

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        Percept.update_from_changeset(self, changeset, update_sender, update_recipient)

        if "tag" in changeset:
            self.tag = Tag.get_or_create(changeset["tag"])
        return self

    __mapper_args__ = {
        'polymorphic_identity': 'tag'
    }


class Mention(Percept):
    """Mention an Identity to notify them"""

    _insert_required = ["id", "created", "modified", "kind", "identity_id",
        "text"]
    _update_required = ["id", "modified"]

    id = db.Column(db.String(32), db.ForeignKey('percept.id'), primary_key=True)

    text = db.Column(db.String(80))

    identity_id = db.Column(db.String(32), db.ForeignKey('identity.id'))
    identity = db.relationship('Identity', backref="mentions")

    def __init__(self, *args, **kwargs):
        Percept.__init__(self, *args, **kwargs)
        self.id = uuid4().hex

        for k in ["identity", "text"]:
            if k not in kwargs:
                raise ValueError("Missing parmeter {}".format(k))

        self.identity = kwargs["identity"]
        self.text = kwargs["text"]

    def __repr__(self):
        return "<Mention @{} [{}]>".format(self.text, self.id[:6])

    @staticmethod
    def create_from_changeset(changeset, update_sender=None, update_recipient=None):
        stub = TagPercept()
        new_percept = Percept.create_from_changeset(changeset, stub=stub,
            update_sender=update_sender, update_recipient=update_recipient)

        new_percept.identity = Identity.get(changeset["identity_id"])
        if new_percept.identity is None:
            raise PersonaNotFoundError("Mention links Identity {}".format(
                changeset["identity_id"]))

        new_percept.text = changeset["text"]

        return new_percept

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        Percept.update_from_changeset(self, changeset, update_sender, update_recipient)

        if "identity_id" in changeset:
            self.identity = Identity.get(changeset["identity_id"])
            if self.identity is None:
                raise PersonaNotFoundError("Mention links Identity {}".format(
                    changeset["identity_id"]))

        if "text" in changeset:
            self.text = changeset["text"]

        return self

    __mapper_args__ = {
        'polymorphic_identity': 'mention'
    }


class LinkedPicturePercept(Percept):
    """A linked picture attachment"""

    __mapper_args__ = {
        'polymorphic_identity': 'linkedpicture'
    }

    _insert_required = ["id", "title", "created", "modified", "source", "url", "kind"]
    _update_required = ["id", "title", "modified", "source", "url"]

    id = db.Column(db.String(32), db.ForeignKey('percept.id'), primary_key=True)

    url = db.Column(db.Text)

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Percept object from a changeset (See Serializable.create_from_changeset). """
        if stub is None:
            stub = LinkedPicturePercept()

        new_percept = Percept.create_from_changeset(changeset,
            stub=stub, update_sender=update_sender, update_recipient=update_recipient)

        new_percept.url = changeset["url"]

        # if "width" in changeset:
        #     new_percept.width = int(changeset["width"])

        # if "height" in changeset:
        #     new_percept.height = int(changeset["height"])

        return new_percept

    @classmethod
    def get_or_create(cls, url, *args, **kwargs):
        """Get or create an instance from a URL

        Args:
            url (String): URL of the Percept to retrieve
            args, kwargs: get passed on to cls.__init__ if a new instance is created

        Raises:
            ValueError: If no url was provided"""

        if url is not None:
            url_hash = sha256("linkedpicture" + url).hexdigest()[:32]
        else:
            raise ValueError("URL parameter must not be None")

        inst = cls.query.filter_by(id=url_hash).first()
        if inst is None:
            logger.debug("Creating new linked picture for hash {}".format(
                url_hash))
            inst = cls(id=url_hash, url=url, *args, **kwargs)

        return inst

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a new Percept object from a changeset (See Serializable.update_from_changeset). """
        raise NotImplementedError


class LinkPercept(Percept):
    """A URL attachment"""

    __mapper_args__ = {
        'polymorphic_identity': 'link'
    }

    _insert_required = ["id", "title", "kind", "created", "modified", "source", "url", "kind"]
    _update_required = ["id", "title", "modified", "source", "url"]

    id = db.Column(db.String(32), db.ForeignKey('percept.id'), primary_key=True)

    url = db.Column(db.Text)

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Percept object from a changeset (See Serializable.create_from_changeset). """
        if stub is None:
            stub = LinkPercept()

        new_percept = Percept.create_from_changeset(changeset,
            stub=stub, update_sender=update_sender, update_recipient=update_recipient)

        new_percept.url = changeset["url"]

        return new_percept

    def get_domain(self):
        """Return the name of this Percept's domain

        Returns:
            string: domain like 'rktik.com'"""

        # Taken from http://stackoverflow.com/questions/9626535/get-domain-name-from-url/9626596#9626596

        from urlparse import urlparse

        parsed_uri = urlparse(self.url)
        try:
            # domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
            rv = parsed_uri.netloc
        except AttributeError, e:
            logger.warning("Error retrieving domain for {}: {}".format(self, e))
            rv = None
        rv = rv[4:] if rv.startswith('www.') else rv
        return rv

    domain = property(get_domain)

    @classmethod
    def get_or_create(cls, url, title=None):
        """Get or create an instance from a URL

        Args:
            url (String): URL of the Percept to retrieve
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

    @cache.memoize(timeout=IFRAME_URL_CACHE_DURATION)
    def iframe_url(self):
        """Return a URL to embed within an iframe if this link's domain provides such

        Returns:
            string: URL to embeddable content
            None: If no method is known to embed content from link's domain
        """
        from urlparse import urlparse
        rv = None

        parsed_uri = urlparse(self.url)
        if parsed_uri.netloc == "www.youtube.com":
            # http://stackoverflow.com/a/8260383
            youtube_re = "^.*((youtu.be\/)|(v\/)|(\/u\/\w\/)|(embed\/)|(watch\?))\??v?=?([^#\&\?]*).*"
            matches = re.search(youtube_re, self.url)
            if matches and matches.groups()[-1] and len(matches.groups()[-1]) == 11:
                video_id = matches.groups()[-1]
                rv = "https://www.youtube.com/embed/{id}".format(id=video_id)

        elif parsed_uri.netloc == "soundcloud.com":
            client_id = os.environ.get("SOUNDCLOUD_CLIENT_ID")
            if not client_id:
                logger.warning("Please set env var SOUNDCLOUD_CLIENT_ID to enable embeds")
            else:
                client = SoundcloudClient(client_id=client_id)
                try:
                    track = client.get('/resolve', url=self.url)
                except (ConnectionError, HTTPError), e:
                    logger.warning("Error connecting to Soundcloud: {}".format(e))
                else:
                    if track:
                        rv = "https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/{track_id}&amp;auto_play=false&amp;hide_related=false&amp;show_comments=true&amp;show_user=true&amp;show_reposts=false&amp;visual=true".format(track_id=track.id)
        return rv

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a new Percept object from a changeset (See Serializable.update_from_changeset). """
        raise NotImplementedError


class TextPercept(Percept):
    """A longform text attachment"""

    __mapper_args__ = {
        'polymorphic_identity': 'text'
    }

    _insert_required = ["id", "title", "kind", "created", "modified", "source", "text", "kind"]
    _update_required = ["id", "title", "modified", "source", "text"]

    id = db.Column(db.String(32), db.ForeignKey('percept.id'), primary_key=True)

    text = db.Column(db.Text)

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Percept object from a changeset (See Serializable.create_from_changeset). """
        if stub is None:
            stub = TextPercept()

        new_percept = Percept.create_from_changeset(changeset,
            stub=stub, update_sender=update_sender, update_recipient=update_recipient)

        new_percept.text = changeset["text"]

        return new_percept

    @classmethod
    def get_or_create(cls, text, source=None):
        """Return percept containing text if it already exists or create it

        Args:
            text (String): Content value of the TextPercept
            source (String): Source description, max 128 chars
        """
        h = sha256(text.encode('utf-8')).hexdigest()[:32]
        percept = TextPercept.query.get(h)

        if percept is None:
            logger.info("Storing new text")
            percept = TextPercept(
                id=h,
                text=text,
                source=source)

        return percept

    def reading_time(self):
        """Return an estimate for reading time based on 200 words per minute

        Returns:
            Reading time as a timedelta object
        """
        word_count = len(self.text.split(" "))
        return datetime.timedelta(minutes=int(word_count / 200))

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a new Percept object from a changeset (See Serializable.update_from_changeset). """
        raise NotImplementedError


class Upvote(Thought):
    """A Upvote is a vote that signals interest in its parent Thought"""

    __mapper_args__ = {
        'polymorphic_identity': 'upvote'
    }

    _insert_required = ["id", "created", "modified", "author_id", "parent_id", "state"]
    _update_required = ["id", "modified", "state"]

    def __repr__(self):
        if ["author_id", "parent_id"] in dir(self):
            return "<Upvote <Persona {}> -> <Thought {}> ({})>".format(
                self.author_id[:6], self.parent_id[:6], self.get_state())
        else:
            return "<Upvote ({})>".format(self.get_state())

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Upvote object from a changeset (See Serializable.create_from_changeset). """
        created_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)

        if stub is not None:
            upvote = stub
            upvote.created = created_dt
            upvote.modified = modified_dt
            upvote.author = None
            upvote.source = changeset["source"],
            upvote.parent_id = None
        else:
            upvote = Upvote(
                id=changeset["id"],
                created=created_dt,
                modified=modified_dt,
                author=None,
                parent=None,
            )

        upvote.set_state(int(changeset["state"]))

        author = Persona.query.get(changeset["author_id"])
        if author is None:
            # TODO: Send request for author
            upvote.author_id = changeset["author_id"]
            if upvote.get_state() >= 0:
                upvote.set_state(1)
        else:
            upvote.author = author

        thought = Thought.query.get(changeset["parent_id"])
        if thought is None:
            logger.warning("Parent Thought for Upvote not found")
            upvote.parent_id = changeset["parent_id"]
        else:
            thought.children.append(upvote)

        return upvote

    def get_state(self):
        """
        Return publishing state of this Upvote.

        Returns:
            Integer:
                -1 -- (disabled)
                 0 -- (active)
                 1 -- (unknown author)
        """
        return UPVOTE_STATES[self.state][0]

    def hot(self):
        return 0

    def set_state(self, new_state):
        """
        Set the publishing state of this Upvote

        Parameters:
            new_state (int) code of the new state as defined in nucleus.UPVOTE_STATES

        Raises:
            ValueError: If new_state is not an Int or not a valid state of this object
        """
        new_state = int(new_state)
        if new_state not in UPVOTE_STATES.keys():
            raise ValueError("{} ({}) is not a valid Upvote state".format(
                new_state, type(new_state)))
        else:
            self.state = new_state

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update a new Upvote object from a changeset (See Serializable.update_from_changeset). """
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        self.modified = modified_dt

        self.set_state(changeset["state"])

        logger.info("Updated {} from changeset".format(self))


class Souma(Serializable, db.Model):
    """A physical machine in the Souma network"""

    __tablename__ = "souma"

    _insert_required = ["id", "modified", "crypt_public", "sign_public", "mindset_id"]
    _version_string = db.Column(db.String(32), default="")

    id = db.Column(db.String(32), primary_key=True)

    crypt_private = db.Column(db.Text)
    crypt_public = db.Column(db.Text)
    sign_private = db.Column(db.Text)
    sign_public = db.Column(db.Text)

    # Relations
    mindset_id = db.Column(db.String(32), db.ForeignKey('mindset.id'))
    mindset = db.relationship('Mindset')

    def __repr__(self):
        return "<Souma [{}]>".format(self.id[:6])

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

    def authorize(self, action, author_id=None):
        """Return True if this Souma authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        return False

    def generate_keys(self):
        """ Generate new RSA keypairs for signing and encrypting. Commit to DB afterwards! """

        # TODO: Store keys encrypted
        rsa1 = RsaPrivateKey.Generate()
        self.sign_private = str(rsa1)
        self.sign_public = str(rsa1.public_key)

        rsa2 = RsaPrivateKey.Generate()
        self.crypt_private = str(rsa2)
        self.crypt_public = str(rsa2.public_key)

    def decrypt(self, cypher):
        """ Decrypt cyphertext using RSA """

        if self.crypt_private == "":
            raise ValueError("Error decrypting: No private encryption key found for {}".format(self))

        key_private = RsaPrivateKey.Read(self.crypt_private)
        return key_private.Decrypt(cypher)

    def encrypt(self, data):
        """ Encrypt data using RSA """

        if self.crypt_public == "":
            raise ValueError("Error encrypting: No public encryption key found for {}".format(self))

        key_public = RsaPublicKey.Read(self.crypt_public)
        return key_public.Encrypt(data)

    def sign(self, data):
        """ Sign data using RSA """
        from base64 import urlsafe_b64encode

        if self.sign_private == "":
            raise ValueError("Error signing: No private signing key found for {}".format(self))

        key_private = RsaPrivateKey.Read(self.sign_private)
        signature = key_private.Sign(data)
        return urlsafe_b64encode(signature)

    @property
    def version(self):
        """Return semantic version object for this Souma"""
        if not hasattr(self, "_version_string"):
            return None
        return semantic_version.Version(self._version_string)

    @version.setter
    def version(self, value):
        self._version_string = str(semantic_version.Version(value))

    def verify(self, data, signature_b64):
        """ Verify a signature using RSA """
        from base64 import urlsafe_b64decode

        if self.sign_public == "":
            raise ValueError("Error verifying: No public signing key found for {}".format(self))

        signature = urlsafe_b64decode(signature_b64)
        key_public = RsaPublicKey.Read(self.sign_public)
        return key_public.Verify(data, signature)


t_mindset_vesicles = db.Table(
    'mindset_vesicles',
    db.Column('mindset_id', db.String(32), db.ForeignKey('mindset.id')),
    db.Column('vesicle_id', db.String(32), db.ForeignKey('vesicle.id'))
)


class Mindset(Serializable, db.Model):
    """
    Mindsets are collections of objects with associated layout information.

    Atributes:
        id: 32 byte ID generated by uuid4().hex
        modified: Datetime of last recorded modification
        author: Persona that created this Mindset
        kind: For what kind of context is this Mindset used
        index: Query for Thoughts that are contained in this Mindset
        vesicles: List of Vesicles that describe this Mindset
    """
    __tablename__ = 'mindset'
    __mapper_args__ = {
        'polymorphic_identity': 'mindset',
        'polymorphic_on': 'kind'
    }

    _insert_required = ["id", "modified", "author_id", "kind", "state"]
    _update_required = ["id", "modified", "index"]

    id = db.Column(db.String(32), primary_key=True)
    modified = db.Column(db.DateTime)
    kind = db.Column(db.String(16))
    state = db.Column(db.Integer, default=0)

    author_id = db.Column(
        db.String(32),
        db.ForeignKey('identity.id', use_alter=True, name="fk_author_id"))
    author = db.relationship('Identity',
        backref=db.backref('mindsets'),
        primaryjoin="Identity.id==Mindset.author_id",
        post_update=True)

    vesicles = db.relationship(
        'Vesicle',
        secondary='mindset_vesicles',
        primaryjoin='mindset_vesicles.c.mindset_id==mindset.c.id',
        secondaryjoin='mindset_vesicles.c.vesicle_id==vesicle.c.id')

    def __contains__(self, key):
        """Return True if the given key is contained in this Mindset.

        Args:
            key: db.model.key to look for
        """
        return (key in self.index)

    def __len__(self):
        return self.index.paginate(1).total

    def __repr__(self):
        return "<{} [{}]>".format(self.name, self.id[:6])

    def authorize(self, action, author_id=None):
        """Return True if this Mindset authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        if Serializable.authorize(self, action, author_id=author_id):
            if self.kind == "blog" and isinstance(self.author, Persona):
                p = Persona.request_persona(self.author_id)
                return p.id == author_id
            elif self.kind == "blog" and isinstance(self.author, Movement):
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

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None):
        """Create a new Mindset object from a changeset

        Args:
            changeset (dict): Contains all keys from self._insert_required

        Returns:
            Mindset: The new object

        Raises:
            ValueError: If a value is invalid
            KeyError: If a required Value is missing
        """
        modified_dt = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)

        author = Identity.query.get(changeset["author_id"])
        if author is None:
            raise PersonaNotFoundError("Mindset author not known")

        if stub is not None:
            new_mindset = stub
            new_mindset.modified = modified_dt
            new_mindset.author = author
            new_mindset.kind = changeset["kind"]
        else:
            if changeset["kind"] == "blog":
                mscls = Blog
            elif changeset["kind"] == "mindspace":
                mscls = Mindspace
            else:
                mscls = Mindset

            new_mindset = mscls(
                id=changeset["id"],
                modified=modified_dt,
                author=author,
                kind=changeset["kind"]
            )

        request_list = list()
        for thought_changeset in changeset["index"]:
            thought = Thought.query.get(thought_changeset["id"])
            thought_changeset_modified = iso8601.parse_date(thought_changeset["modified"]).replace(tzinfo=None)

            if thought is None or thought.get_state() == -1 or thought.modified < thought_changeset_modified:
                request_list.append({
                    "type": "Thought",
                    "id": thought_changeset["id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })

                if thought is None:
                    thought_author = Identity.query.get(thought_changeset["author_id"])
                    if thought_author is not None:
                        thought = Thought(
                            id=thought_changeset["id"],
                            modified=thought_changeset_modified,
                            author=thought_author,
                            mindset_id=new_mindset.id
                        )
                        thought.set_state(-1)
                        db.session.add(thought)
                        db.session.commit()

        db.session.add(new_mindset)
        db.session.commit()

        for req in request_list:
            request_objects.send(Mindset.create_from_changeset, message=req)

        return new_mindset

    def export(self, exclude=[], include=None, update=False):
        ex = set(exclude + ["index", ])
        data = Serializable.export(self, exclude=ex, include=include, update=update)

        data["index"] = list()
        for thought in self.index.filter('Thought.state >= 0'):
            data["index"].append({
                "id": thought.id,
                "modified": thought.modified.isoformat(),
                "author_id": thought.author.id
            })

        return data

    def get_absolute_url(self):
        """Return URL for this Mindset depending on kind"""
        raise NotImplementedError("Base Mindset doesn't have its own URL scheme")

    def get_state(self):
        """
        Return publishing state of this thought.

        Returns:
            Integer:
                -2 -- deleted
                -1 -- unavailable
                0 -- published
                1 -- draft
                2 -- private
                3 -- updating
        """
        return THOUGHT_STATES[self.state][0]

    @property
    def name(self):
        """Return an identifier for this Mindset that can be used in UI

        Returns:
            string: Name for this Mindset
        """
        rv = "Mindset by {}".format(self.author.username)
        return rv

    def set_state(self, new_state):
        """
        Set the publishing state of this thought

        Parameters:
            new_state (int) code of the new state as defined in nucleus.THOUGHT_STATES

        Raises:
            ValueError: If new_state is not an Int or not a valid state of this object
        """
        new_state = int(new_state)
        if new_state not in THOUGHT_STATES.keys():
            raise ValueError("{} ({}) is not a valid thought state").format(
                new_state, type(new_state))
        else:
            self.state = new_state

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update the Mindset's index using a changeset

        Args:
            changeset (dict): Contains a key for every attribute to update

        Raises:
            ValueError: If a value in the changeset is invalid
        """
        # Update modified
        modified = iso8601.parse_date(changeset["modified"]).replace(tzinfo=None)
        self.modified = modified

        # Update index
        remove_thoughts = set([s.id for s in self.index if s is not None])
        added_thoughts = list()
        request_list = list()
        for thought_changeset in changeset["index"]:
            thought = Thought.query.get(thought_changeset["id"])
            thought_changeset_modified = iso8601.parse_date(thought_changeset["modified"]).replace(tzinfo=None)

            if thought is not None and thought.id in remove_thoughts:
                remove_thoughts.remove(thought.id)

            if thought is None or thought.get_state() == -1 or thought.modified < thought_changeset_modified:
                # No copy of Thought available or copy is outdated

                request_list.append({
                    "type": "Thought",
                    "id": thought_changeset["id"],
                    "author_id": update_recipient.id,
                    "recipient_id": update_sender.id,
                })

                if thought is None:
                    thought_author = Persona.query.get(thought_changeset["author_id"])
                    if thought_author is not None:
                        thought = Thought(
                            id=thought_changeset["id"],
                            modified=thought_changeset_modified,
                            author=thought_author
                        )
                        thought.set_state(-1)
                        db.session.add(thought)
                        db.session.commit()

            self.index.append(thought)
            added_thoughts.append(thought)

        for s_id in remove_thoughts:
            s = Thought.query.get(s_id)
            self.index.remove(s)

        logger.info("Updated {}: {} thoughts added, {} requested, {} removed".format(
            self, len(added_thoughts), len(request_list), len(remove_thoughts)))

        for req in request_list:
            request_objects.send(Mindset.create_from_changeset, message=req)


class Mindspace(Mindset):
    """Model internal thoughts of an Identity"""

    __mapper_args__ = {
        'polymorphic_identity': 'mindspace'
    }

    def authorize(self, action, author_id=None):
        if isinstance(self.author, Persona):
            rv = (author_id == self.author.id)
        elif isinstance(self.author, Movement):
            rv = self.author.authorize(action, author_id)
        return rv

    def get_absolute_url(self):
        """Return URL for this Mindset depending on kind"""
        rv = None

        if isinstance(self.author, Movement):
            m = Movement.query.filter(Movement.mindspace_id == self.id).first()
            rv = url_for("web.movement_mindspace", id=m.id)

        elif isinstance(self.author, Persona):
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
            if isinstance(self.author, Movement):
                rv = (author_id == self.author.id) \
                    or (author_id == self.author.admin.id)
            else:
                rv = (author_id == self.author.id)
        return rv

    def get_absolute_url(self):
        """Return URL for this Mindset depending on kind"""
        rv = None

        if isinstance(self.author, Movement):
            m = Movement.query.filter(Movement.blog_id == self.id).first()
            rv = url_for("web.movement_blog", id=m.id)

        elif isinstance(self.author, Persona):
            p = Persona.query.filter(Persona.blog_id == self.id).first()
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

    other = db.relationship("Identity",
        primaryjoin="identity.c.id==mindset.c.other_id")
    other_id = db.Column(db.String(32), db.ForeignKey(
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


class MovementMemberAssociation(db.Model):
    """Associates Personas with Movements"""

    __tablename__ = 'movementmember_association'
    __table_args__ = (db.UniqueConstraint(
        'movement_id', 'persona_id', name='_mma_uc'),)

    id = db.Column(db.Integer, primary_key=True)
    movement_id = db.Column(db.String(32), db.ForeignKey('movement.id'))
    persona_id = db.Column(db.String(32), db.ForeignKey('persona.id'))
    persona = db.relationship("Persona",
        backref="movement_assocs", lazy="joined")

    # Role may be either 'admin' or 'member'
    active = db.Column(db.Boolean, default=True)
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    description = db.Column(db.Text)
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    role = db.Column(db.String(16), default="member")
    invitation_code = db.Column(db.String(32))

    def __repr__(self):
        return "<Membership <Movement {}> <Persona {}> ({})>".format(
            self.movement.id[:6], self.persona.id[:6], self.role)


t_members = db.Table(
    'members',
    db.Column('movement_id', db.String(32), db.ForeignKey('movement.id')),
    db.Column('persona_id', db.String(32), db.ForeignKey('persona.id'))
)

t_movement_vesicles = db.Table(
    'movement_vesicles',
    db.Column('movement_id', db.String(32), db.ForeignKey('movement.id')),
    db.Column('vesicle_id', db.String(32), db.ForeignKey('vesicle.id'))
)


class Movement(Identity):
    """Represents an entity that is comprised of users collaborating on thoughts

    Attributes:
        id (String): 32 byte ID of this movement
        description (String): Text decription of what this movement is about
        admin (Persona): Person that is allowed to make structural changes to the movement_id

    """

    __tablename__ = "movement"
    __mapper_args__ = {'polymorphic_identity': 'movement'}

    _insert_required = Identity._insert_required + ["admin_id", "description", "blog_id"]
    _update_required = Identity._update_required + ["state"]

    id = db.Column(db.String(32), db.ForeignKey('identity.id'), primary_key=True)

    description = db.Column(db.Text)
    state = db.Column(db.Integer, default=0)
    private = db.Column(db.Boolean(), default=False)

    # Relations
    admin_id = db.Column(db.String(32), db.ForeignKey('persona.id'))
    admin = db.relationship("Persona", primaryjoin="persona.c.id==movement.c.admin_id")

    members = db.relationship("MovementMemberAssociation",
        backref="movement",
        lazy="dynamic")

    def __init__(self, *args, **kwargs):
        """Attach index mindset to new movements"""
        Identity.__init__(self, *args, **kwargs)
        self.blog = Blog(
            id=uuid4().hex,
            author=self,
            modified=self.created)

        self.mindspace = Mindspace(
            id=uuid4().hex,
            author=self,
            modified=self.created)

    def __repr__(self):
        try:
            name = self.username.encode('utf-8')
        except AttributeError:
            name = "(name encode error)"

        return "<Movement @{} [{}]>".format(name, self.id[:6])

    def active_member(self, persona=None):
        """Return True if persona or currently active Persona is an active
            member or admin

        Args:
            persona (Persona): Optional Persona. Will default to active Persona
                if left blank

        Returns:
            boolean: True if active member
        """
        rv = False

        if persona is None and current_user.is_anonymous() is False:
            persona = current_user.active_persona

        if persona:
            gms = MovementMemberAssociation.query \
                .filter_by(persona=persona) \
                .filter_by(active=True) \
                .filter_by(movement=self) \
                .first()

            rv = True if gms else False
        return rv

    def add_member(self, persona):
        """Add a Persona as member to this movement

        Args:
            persona (Persona): Persona object to be added
        """
        if persona not in self.members:
            self.members.append(persona)

    @cache.memoize(timeout=ATTENTION_CACHE_DURATION)
    def get_attention(self):
        """Return a numberic value indicating attention this Movement has received

        Returns:
            integer: Attention as a positive integer
        """
        timer = ExecutionTimer()

        thoughts = self.blog.index \
            .filter(Thought.state >= 0) \
            .filter(Thought.kind != "upvote").all()

        thoughts += self.mindspace.index \
            .filter(Thought.state >= 0) \
            .filter(Thought.kind != "upvote").all()

        rv = int(sum([t.hot() for t in thoughts]) * ATTENTION_MULT)
        timer.stop("Generated attention value for {}".format(self))
        return rv

    attention = property(get_attention)

    def authorize(self, action, author_id=None):
        """Return True if this Movement authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        rv = False
        if Serializable.authorize(self, action, author_id=author_id):
            if action == "read":
                rv = True
                if self.private:
                    member = MovementMemberAssociation.query \
                        .filter_by(movement=self) \
                        .filter_by(active=True) \
                        .filter_by(persona_id=author_id) \
                        .first()

                    rv = member is not None
            else:
                rv = self.admin_id == author_id
        return rv

    @property
    def contacts(self):
        """Alias for Movememt.members for compatibility with Persona class"""
        return self.members.filter_by(active=True)

    @staticmethod
    def create_from_changeset(changeset, stub=None, update_sender=None, update_recipient=None, request_sources=True):
        """Create a new movement from changeset"""
        movement = Identity.create_from_changeset(changeset,
            stub=stub,
            update_sender=update_sender,
            update_recipient=update_recipient,
            kind=Movement,
            request_sources=request_sources)

        movement.description = changeset["description"]

        if "state" in changeset:
            movement.set_state(changeset["state"])

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

        movement.admin = admin

        if "members" in changeset:
            mc = movement.update_members(changeset["members"])
            for m in mc:
                request_list.append({
                    "type": "Persona",
                    "id": m,
                    "author_id": update_recipient.id if update_recipient else None,
                    "recipient_id": update_sender.id if update_sender else None,
                })

        if request_sources:
            for req in request_list:
                request_objects.send(Movement.create_from_changeset, message=req)

        return movement

    def current_role(self):
        """Return role of the currently active Persona

        Returns:
            String: Name  of the role. One of "anonymous", "visitor",
                "member", "admin"
        """
        if not current_user or current_user.is_anonymous():
            rv = "anonymous"
        else:
            gma = MovementMemberAssociation.query.filter_by(movement_id=self.id). \
                filter_by(persona_id=current_user.active_persona.id).first()

            if gma is None:
                rv = "visitor"
            else:
                rv = gma.role
        return rv

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

    def get_absolute_url(self):
        """Return URL for this movement's mindspace page"""
        return url_for("web.movement", id=self.id)

    def get_state(self):
        """
        Return publishing state of this Movement. (temporarily uses percept states)

        Returns:
            Integer:
                -2 -- deleted
                -1 -- unavailable
                0 -- published
                1 -- draft
                2 -- private
                3 -- updating
        """
        return PERCEPT_STATES[self.state][0]

    @cache.memoize(timeout=MEMBER_COUNT_CACHE_DURATION)
    def member_count(self):
        """Return number of active members in this movement

        Returns:
            int: member count
        """
        timer = ExecutionTimer()
        rv = MovementMemberAssociation.query \
            .filter_by(movement=self) \
            .filter_by(active=True) \
            .count()

        timer.stop("Generated member count for {}".format(self))
        return int(rv)

    @cache.memoize(timeout=MINDSPACE_TOP_THOUGHT_CACHE_DURATION)
    def mindspace_top_thought(self, count=15):
        """Return count top thoughts from mindspace

        Returns:
            list: Dicts with key 'id'
        """
        timer = ExecutionTimer()
        selection = self.mindspace.index.filter(Thought.state >= 0).all()
        rv = [t.id for t in sorted(
            selection, key=Thought.hot, reverse=True)[:count]]
        timer.stop("Generated {} mindspace top thought".format(self))
        return rv

    def promotion_check(self, thought):
        """Promote a Thought to this movement's blog if it has enough upvotes

        Args:
            thought (Thought): The thought to be promoted

        Returns:
            None: If no promotion was done
            Thought: The new blog post
        """
        rv = None
        if not thought._blogged and thought.mindset \
                and thought.mindset.kind == "mindspace":
            if thought.upvote_count() >= self.required_votes():
                logger.info("Promoting {} to {} blog".format(thought, self))
                clone = Thought.clone(thought, self, self.blog)
                upvote = Upvote(id=uuid4().hex,
                    author=self, parent=clone, state=0)
                clone.children.append(upvote)
                thought._blogged = True
                movement_chat.send(self, room_id=self.mindspace.id,
                    message="New promotion! Check the blog")
                rv = clone
        return rv

    def remove_member(self, persona):
        """Remove a Persona from this movement's local member list

        Args:
            persona (Persona): Persona object to be removed
        """
        if persona in self.members:
            self.members.remove(persona)

    def required_votes(self):
        """Return the number of votes required to promote a Thought ot the blog

        n = round(count/100 + 2/count + (log(1.65,count)))
        with count being the number of members this movement has

        Returns:
            int: Number of votes required
        """
        from math import log
        c = self.member_count()
        rv = int(c / 100.0 + 0.8 / c + log(c, 1.65)) if c > 0 else 1
        return rv

    def set_state(self, new_state):
        """
        Set the publishing state of this Movement (temporarily uses percept states)

        Parameters:
            new_state (int) code of the new state as defined in nucleus.PERCEPT_STATES

        Raises:
            ValueError: If new_state is not an Int or not a valid state of this object
        """
        new_state = int(new_state)
        if new_state not in PERCEPT_STATES.keys():
            raise ValueError("{} ({}) is not a valid percept state").format(
                new_state, type(new_state))
        else:
            self.state = new_state

    @classmethod
    @cache.memoize(timeout=TOP_MOVEMENT_CACHE_DURATION)
    def top_movements(cls, count=10):
        """Return a list of top movements as measured by member count

        Returns:
            list: List of dicts with keys 'id', 'username'
        """
        timer = ExecutionTimer()
        movements = Movement.query \
            .join(MovementMemberAssociation) \
            .order_by(func.count(MovementMemberAssociation.persona_id)) \
            .group_by(MovementMemberAssociation.persona_id) \
            .group_by(Movement)

        rv = list()
        for m in movements.limit(count):
            rv.append({
                "id": m.id,
                "username": m.username
            })

        timer.stop("Generated top movements")
        return rv

    def update_from_changeset(self, changeset, update_sender=None, update_recipient=None):
        """Update movement. See Serializable.update_from_changeset"""
        Identity.update_from_changeset(self, changeset,
            update_sender=update_sender, update_recipient=update_recipient)

        logger.info("Now applying Movement-specific updates for {}".format(self))

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
            request_objects.send(Movement.update_from_changeset, message=req)

    def update_members(self, new_member_list):
        """Update Movements's members from a list of the new members.

        This method may only be used with an authoritative list of movement
        members (i.e. from the movement admin).

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

    def voting_done(self, thought):
        """Provide a value in [0,1] indicating how many votes have been cast
            toward promoting a thought. For already blogged thoughts 1 is also
            returned

        Returns:
            float: Ratio of required votes already cast
        """
        if thought._blogged:
            rv = 1
        else:
            req = self.required_votes()
            rv = 1
            if req > 0:
                rv = min([float(thought.upvote_count()) /
                    self.required_votes(), 1.0])
        return rv
