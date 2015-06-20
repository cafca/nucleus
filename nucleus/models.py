
import datetime
import json
import iso8601
import logging
import semantic_version
import re

from base64 import b64encode, b64decode
from flask import url_for, current_app
from flask.ext.login import current_user, UserMixin
from hashlib import sha256
from keyczar.keys import RsaPrivateKey, RsaPublicKey
from uuid import uuid4

from . import UPVOTE_STATES, THOUGHT_STATES, PERCEPT_STATES, ATTACHMENT_KINDS, \
    PersonaNotFoundError, UnauthorizedError, notification_signals, \
    CHANGE_TYPES
from .helpers import epoch_seconds, process_attachments

from database import cache, db

request_objects = notification_signals.signal('request-objects')
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


class PersonaAssociation(db.Model):
    """Connects user accounts and personas"""
    __tablename__ = "persona_association"
    left_id = db.Column(db.String(32), db.ForeignKey('user.id'), primary_key=True)
    right_id = db.Column(db.String(32), db.ForeignKey('persona.id'), primary_key=True)
    persona = db.relationship("Persona", backref="associations")


class User(UserMixin, db.Model):
    """A user of the website"""

    __tablename__ = 'user'

    id = db.Column(db.String(32), primary_key=True, default=uuid4().hex)

    active = db.Column(db.Boolean(), default=True)
    authenticated = db.Column(db.Boolean(), default=True)
    created = db.Column(db.DateTime)
    email = db.Column(db.String(128))
    modified = db.Column(db.DateTime)
    pw_hash = db.Column(db.String(64))
    validated_on = db.Column(db.DateTime)
    signup_code = db.Column(db.String(128))

    # Relations
    active_persona = db.relationship("Persona")
    active_persona_id = db.Column(db.String(32), db.ForeignKey('persona.id'))

    associations = db.relationship('PersonaAssociation', lazy="dynamic", backref="user")

    def __repr__(self):
        return "<User {}>".format(self.email.decode('utf-8'))

    def check_password(self, password):
        """Return True if password matches user password

        Args:
            password (String): Password entered by user in login form
        """
        pw_hash = sha256(password).hexdigest()
        return self.pw_hash == pw_hash

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

    def has_blogged(self, thought):
        """Return True if this Identity has blogged thought

        When a post is blogged, the blog post is created as a reply to the
        original post, hence this is checking whether this Identity has replied
        to the thought on its blog

        Args:
            thought (Thought): Thought to check
        """
        count = self.blog.index \
            .filter(Thought.parent == thought) \
            .filter(Thought.author == self) \
            .count()
        return count > 0

    @staticmethod
    def list_controlled():
        if not current_user.is_anonymous() and current_user.active_persona is not None:
            controlled_user = User.query \
                .join(PersonaAssociation) \
                .filter(PersonaAssociation.right_id == current_user.active_persona.id) \
                .first()

            return [asc.persona for asc in controlled_user.associations] if controlled_user else []
        else:
            return []

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

t_movements_followed = db.Table('movements_followed',
    db.Column('persona_id', db.String(32), db.ForeignKey('persona.id')),
    db.Column('movement_id', db.String(32), db.ForeignKey('movement.id'))
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

    auth = db.Column(db.String(32), default=uuid4().hex)
    last_connected = db.Column(db.DateTime, default=datetime.datetime.now())
    # Myelin offset stores the date at which the last Vesicle receieved from Myelin was created
    myelin_offset = db.Column(db.DateTime)
    email = db.Column(db.String(120))
    session_id = db.Column(db.String(32), default=uuid4().hex)

    # Relations
    contacts = db.relationship('Persona',
        secondary='contacts',
        lazy="dynamic",
        remote_side='contacts.c.right_id',
        primaryjoin='contacts.c.left_id==persona.c.id',
        secondaryjoin='contacts.c.right_id==persona.c.id')

    index_id = db.Column(db.String(32), db.ForeignKey('mindset.id'))
    index = db.relationship('Mindset', primaryjoin='mindset.c.id==persona.c.index_id')

    movements_followed = db.relationship('Movement',
        secondary='movements_followed',
        primaryjoin='movements_followed.c.persona_id==persona.c.id',
        secondaryjoin='movements_followed.c.movement_id==movement.c.id')

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
        movements_to_check = set(changeset["movements"] + changeset["movements_followed"])
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

    def export(self, exclude=[], include=None, update=False):
        exclude = set(exclude + ["contacts", "movements", "movements_followed"])
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

        data["movements_followed"] = list()
        for movement in self.movements_followed:
            data["movements_followed"].append({
                "id": movement.id
            })

        return data

    def get_absolute_url(self):
        return url_for('web.persona', id=self.id)

    def get_email_hash(self):
        """Return sha256 hash of this user's email address"""
        return sha256(self.email).hexdigest()

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

    def timeout(self):
        return self.last_connected + current_app.config['SESSION_EXPIRATION_TIME']

    def toggle_following_movement(self, movement):
        """Toggle whether this Persona is following a movement.

        Args:
            movement (Movement): Movement entity to be (un)followed

        Returns:
            boolean -- True if the movement is now being followed, False if not
        """
        following = False

        try:
            self.movements_followed.remove(movement)
            logger.info("{} is not following {} anymore".format(self, movement))
        except ValueError:
            self.movements_followed.append(movement)
            following = True
            logger.info("{} is now following {}".format(self, movement))

        return following

    def toggle_movement_membership(self, movement, role="member"):
        """Toggle whether this Persona is member of a movement.

        Also enables movement following for this Persona/Movement.

        Args:
            movement (Movement): Movement entity to be become member of
            role (String): What role to take in the movement. May be "member"
                or "admin"

        Returns:
            Updated MovementMemberAssociation object or None if it was deleted
        """
        if movement not in self.movements_followed:
            logger.info("Setting {} to follow {}.".format(self, movement))
            self.toggle_following_movement(movement)

        gms = MovementMemberAssociation.query.filter_by(movement_id=movement.id). \
            filter_by(persona_id=self.id).first()

        if gms is None:
            logger.info("Enabling membership of {} in {}".format(self, movement))
            gms = MovementMemberAssociation(
                persona=self,
                movement_id=movement.id,
                role=role,
            )
            rv = gms
        else:
            if self.id == movement.admin_id:
                raise NotImplementedError("Admin can't leave the movement")
            logger.info("Removing membership of {} in {}".format(self, movement))
            gms.query.delete()
            rv = None
        return rv

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
        movements_2 = changeset.get('movements_followed') or []
        movements_to_check = movements_1 + movements_2

        for movement_info in movements_to_check:
            movement = Movement.query.get(movement_info["id"])
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

    @property
    def user(self):
        return self.associations[0].user


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
    url = db.Column(db.Text)

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

    def __init__(self, mention, author, url):
        super(MentionNotification, self).__init__()
        self.text = "{} mentioned you in a Thought".format(author.username),
        self.url = url,
        self.source = author.username,
        self.recipient = mention.identity


class ReplyNotification(Notification):
    __mapper_args__ = {
        'polymorphic_identity': 'reply_notification'
    }

    def __init__(self, parent_thought, author, url):
        super(ReplyNotification, self).__init__()
        self.text = "{} replied to your Thought".format(author.username),
        self.url = url,
        self.source = author.username,
        self.recipient = parent_thought.author


class DialogueNotification(Notification):
    __mapper_args__ = {
        'polymorphic_identity': 'dialogue_notification'
    }

    def __init__(self, author, recipient):
        super(DialogueNotification, self).__init__()
        self.text = "{} sent you a private message".format(author.username),
        self.url = url_for("web.persona", id=author.id),
        self.source = author.username,
        self.recipient = recipient


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

    # Relations
    author = db.relationship('Identity',
        backref=db.backref('thoughts'),
        primaryjoin="identity.c.id==thought.c.author_id")
    author_id = db.Column(db.String(32), db.ForeignKey('identity.id'))

    mindset = db.relationship('Mindset',
        primaryjoin='mindset.c.id==thought.c.mindset_id',
        backref=db.backref('index', lazy="dynamic"))
    mindset_id = db.Column(db.String(32), db.ForeignKey('mindset.id'))

    parent = db.relationship('Thought',
        primaryjoin='and_(remote(Thought.id)==Thought.parent_id, Thought.state>=0)',
        backref=db.backref('children', lazy="dynamic"),
        remote_side='Thought.id')
    parent_id = db.Column(db.String(32), db.ForeignKey('thought.id'))

    percept_assocs = db.relationship("PerceptAssociation",
        backref="thought",
        lazy="dynamic")

    vesicles = db.relationship('Vesicle',
        secondary='thought_vesicles',
        primaryjoin='thought_vesicles.c.thought_id==thought.c.id',
        secondaryjoin='thought_vesicles.c.vesicle_id==vesicle.c.id')

    def __repr__(self):
        text = self.text.encode('utf-8')
        return "<Thought {}: {}>".format(
            self.id[:6],
            (text[:24] if len(text) <= 24 else text[:22] + ".."))

    def authorize(self, action, author_id=None):
        """Return True if this Thought authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        if Serializable.authorize(self, action, author_id=author_id):
            if isinstance(self.author, Movement):
                return author_id == self.author.admin_id
            else:
                return author_id == self.author.id
        return False

    @property
    def attachments(self):
        pa = self.percept_assocs \
            .join(Percept) \
            .filter(Percept.kind.in_(ATTACHMENT_KINDS))
        rv = dict()

        for category in ATTACHMENT_KINDS:
            rv[category] = pa.filter(Percept.kind == category).all()

        rv["tag"] = pa.filter(Percept.kind == "tag").all()

        return rv

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
        thought_modified = datetime.datetime.utcnow()

        new_thought = cls(
            id=thought_id,
            text=thought.text,
            author=author,
            parent=thought,
            created=thought.created,
            modified=thought_modified,
            mindset=mindset)

        for pa in thought.percept_assocs:
            assoc = PerceptAssociation(
                thought=new_thought, percept=pa.percept, author=author)
            new_thought.percept_assocs.append(assoc)

        return new_thought

    @property
    def comments(self):
        return self.children.filter_by(kind="thought")

    def comment_count(self):
        """
        Return the number of comemnts this Thought has receieved

        Returns:
            Int: Number of comments
        """
        return self.comments.filter_by(state=0).count()

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
            logger.info("Set new thought author to active persona")
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
            mindset=mindset)

        if extract_percepts:
            text, percepts = process_attachments(instance.text)
            instance.text = text
            logger.info("Extracted {} percepts from title".format(len(percepts)))

            if longform and len(longform) > 0:
                lftext, lfpercepts = process_attachments(longform)
                percepts = percepts.union(lfpercepts)
                logger.info("Extracted {} percepts from longform".format(len(percepts)))

                lftext_percept = TextPercept.get_or_create(lftext,
                    source=longform_source)
                percepts.add(lftext_percept)
                logger.info("Attached longform content")

            for percept in percepts:
                if isinstance(percept, Mention):
                    notifications.append(MentionNotification(percept,
                        author, url_for('web.thought', id=thought_id)))

                assoc = PerceptAssociation(
                    thought=instance, percept=percept, author=author)
                instance.percept_assocs.append(assoc)
                logger.info("Attached {} to new {}".format(percept, instance))

        if parent and parent.author != author:
            notifications.append(ReplyNotification(parent_thought=parent,
                author=author, url=url_for('web.thought', id=thought_id)))

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

    def get_absolute_url(self, mindset_id):
        return url_for('web.thought', mindset_id=mindset_id, id=self.id)

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
        """i reddit"""
        from math import log
        # Uncomment to assign a score with analytics.score
        # s = score(self)
        s = self.upvote_count()
        order = log(max(abs(s), 1), 10)
        sign = 1 if s > 0 else -1 if s < 0 else 0
        return round(order + sign * epoch_seconds(self.created) / 45000, 7)

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
            self.state = new_state

    @property
    def tags(self):
        return self.percept_assocs.join(Percept).filter(Percept.kind == "tag")

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

        upvote = self.upvotes.filter_by(author=current_user.active_persona).first()

        if upvote is None or upvote.state < 0:
            return False
        else:
            return True

    @property
    def upvotes(self):
        """Returns a query for all upvotes, including disabled ones"""
        return self.children.filter_by(kind="upvote")

    @cache.memoize(timeout=10)
    def upvote_count(self):
        """
        Return the number of verified upvotes this Thought has receieved

        Returns:
            Int: Number of upvotes
        """
        return self.upvotes.filter(Upvote.state >= 0).count()

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
            old_state = upvote.get_state()
            upvote.set_state(-1) if upvote.state == 0 else upvote.set_state(0)
        else:
            old_state = False
            upvote = Upvote(id=uuid4().hex, author=author, parent=self)
            self.children.append(upvote)

        # Commit Upvote
        db.session.add(self)
        db.session.commit()
        cache.delete_memoized(self.upvote_count)
        logger.info("{verb} {obj}".format(verb="Toggled" if old_state else "Added", obj=upvote, ))

        return upvote


class PerceptAssociation(db.Model):
    """Associates Percepts with Thoughts, defining an author for the connection"""

    __tablename__ = 'percept_association'

    percept_id = db.Column(db.String(32), db.ForeignKey('percept.id'), primary_key=True)
    thought_id = db.Column(db.String(32), db.ForeignKey('thought.id'), primary_key=True)

    author_id = db.Column(db.String(32), db.ForeignKey('identity.id'))
    author = db.relationship("Identity", backref="percept_assocs")
    percept = db.relationship("Percept", backref="thought_assocs")

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
            logger.info("Creating new linked picture for hash {}".format(
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

    def favicon_url(self):
        """Return the URL of this Percept's domain favicon

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

    def __str__(self):
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
    modified = db.Column(db.DateTime, default=datetime.datetime.utcnow())
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

    def get_absolute_url(self):
        """Return URL for this Mindset depending on kind"""
        rv = None

        if isinstance(self.author, Movement):
            m = Movement.query.filter(Movement.blog_id == self.id).first()
            rv = url_for("web.movement_blog", id=m.id)

        elif isinstance(self.author, Persona):
            p = Persona.query.filter(Persona.blog_id == self.id).first()
            rv = url_for("web.persona", id=p.id)

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

    def get_absolute_url(self):
        """Return URL for this Mindset depending on kind"""
        rv = None

        if current_user.is_anonymous():
            rv = None
        else:
            if current_user.active_persona == self.author:
                rv = url_for("web.persona", id=self.other)
            elif current_user.active_persona == self.other:
                rv = url_for("web.persona", id=self.author)

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
        if not current_user.is_anonymous():
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

    movement_id = db.Column(db.String(32), db.ForeignKey('movement.id'), primary_key=True)
    persona_id = db.Column(db.String(32), db.ForeignKey('persona.id'), primary_key=True)
    persona = db.relationship("Persona", backref="movement_assocs")

    # Role may be either 'admin' or 'member'
    active = db.Column(db.Boolean, default=True)
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    description = db.Column(db.Text)
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    role = db.Column(db.String(16), default="member")


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

    def add_member(self, persona):
        """Add a Persona as member to this movement

        Args:
            persona (Persona): Persona object to be added
        """
        if persona not in self.members:
            self.members.append(persona)

    def authorize(self, action, author_id=None):
        """Return True if this Movement authorizes `action` for `author_id`

        Args:
            action (String): Action to be performed (see Synapse.CHANGE_TYPES)
            author_id (String): Persona ID that wants to perform the action

        Returns:
            Boolean: True if authorized
        """
        if Serializable.authorize(self, action, author_id=author_id):
            return self.admin_id == author_id
        return False

    @property
    def contacts(self):
        """Alias for Movememt.members for compatibility with Persona class"""
        return self.members

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

    @property
    def member_count(self):
        """Return number of active members in this movement

        Returns:
            int: member count
        """
        return self.members.count()

    def remove_member(self, persona):
        """Remove a Persona from this movement's local member list

        Args:
            persona (Persona): Persona object to be removed
        """
        if persona in self.members:
            self.members.remove(persona)

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
