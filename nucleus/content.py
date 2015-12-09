# -*- coding: utf-8 -*-
"""
    nucleus.content
    ~~~~~

    Content and attachment models

    :copyright: (c) 2015 by Vincent Ahrend.
"""
import datetime
import os
import re

import context
import identity
import jobs

from collections import defaultdict
from flask import url_for
from flask.ext.login import current_user
from hashlib import sha256
from uuid import uuid4
from requests.exceptions import ConnectionError, HTTPError
from soundcloud import Client as SoundcloudClient
from sqlalchemy import Column, Integer, String, Boolean, DateTime, \
    ForeignKey, Text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship, backref

from . import ATTACHMENT_KINDS, logger, TOP_THOUGHT_CACHE_DURATION, \
    UPVOTE_CACHE_DURATION, ExecutionTimer, PersonaNotFoundError, \
    UnauthorizedError, IFRAME_URL_CACHE_DURATION
from .base import Model, BaseModel
from .connections import cache, db
from .helpers import process_attachments


class Thought(Model):
    """A Thought represents a post"""

    __tablename__ = "thought"

    __mapper_args__ = {
        'polymorphic_identity': 'thought',
        'polymorphic_on': 'kind'
    }

    id = Column(String(32), primary_key=True)
    context_length = Column(Integer(), default=3)
    created = Column(DateTime(), default=datetime.datetime.utcnow())
    modified = Column(DateTime(), default=datetime.datetime.utcnow())
    kind = Column(String(32))
    state = Column(Integer(), default=0)
    text = Column(Text)
    posted_from = Column(String(64))

    _comment_count = Column(Integer())
    _upvotes = Column(Integer())
    _blogged = Column(Boolean, default=False)

    # Relations
    author = relationship('Identity',
        backref=backref('thoughts'),
        primaryjoin="identity.c.id==thought.c.author_id", lazy="joined")
    author_id = Column(String(32), ForeignKey('identity.id'))

    mindset = relationship('Mindset',
        primaryjoin='mindset.c.id==thought.c.mindset_id',
        backref=backref('index', lazy="dynamic"))
    mindset_id = Column(String(32), ForeignKey('mindset.id'))

    parent = relationship('Thought',
        primaryjoin='and_(remote(Thought.id)==Thought.parent_id, Thought.state>=0)',
        backref=backref('children', lazy="joined"),
        remote_side='Thought.id')
    parent_id = Column(String(32), ForeignKey('thought.id'))

    percept_assocs = relationship("PerceptAssociation",
        backref="thought",
        lazy="joined")

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

        if BaseModel.authorize(self, action, author_id=author_id):
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
                elif isinstance(self.author, identity.Movement) \
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

        if mindset is not None and isinstance(mindset, context.Dialogue):
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

        jobs.refresh_recent_thoughts.delay()
        if instance.mindset and isinstance(instance.mindset, context.Dialogue):
            jobs.refresh_conversation_lists.delay(instance.mindset.id)

        return {
            "instance": instance,
            "notifications": notifications
        }

    def get_absolute_url(self):
        return url_for('web.thought', id=self.id)

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

    def get_tags(self):
        return self.percept_assocs.join(Percept).filter(Percept.kind == "tag")

    tags = property(get_tags)

    @classmethod
    @cache.memoize(timeout=TOP_THOUGHT_CACHE_DURATION)
    def top_thought(cls, persona=None, filter_blogged=False, session=None):
        """Return up to 10 hottest thoughts as measured by Thought.hot

        Args:
            persona (Persona): Restricts the result to be from the persona's
                subscriptions
            filter_blogged (Boolean): Don't include thoughts in mindspaces
                that also exist in the corresponding blog

        Returns:
            list: List of thought ids
        """
        timer = ExecutionTimer()

        if session is None:
            session = db.session

        top_post_selection = session.query(cls).filter(cls.state >= 0)

        if filter_blogged:
            top_post_selection = top_post_selection.filter_by(_blogged=False)

        if not isinstance(persona, identity.Persona):
            top_post_selection = top_post_selection \
                .join(context.Mindset) \
                .filter(context.Mindset.kind == "blog")

        else:
            sources = persona.frontpage_sources()
            top_post_selection = top_post_selection.filter(
                Thought.mindset_id.in_(list(sources)))

        top_post_selection = sorted(top_post_selection, key=cls.hot, reverse=True)[:10]

        rv = [t.id for t in top_post_selection]

        timer.stop("Generated frontpage for {}".format(
            persona if persona else "anonymous users"))
        return rv

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
    def upvote_count(self, session=None):
        """
        Return the number of verified upvotes this Thought has receieved

        Returns:
            Int: Number of upvotes
        """
        rv = self._upvotes

        if rv is None:
            self._upvotes = self.upvotes.filter(Upvote.state >= 0).count()
            rv = self._upvotes
            session.add(self)
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
            author = identity.Persona.query.get(author_id)

        if author is None:
            raise PersonaNotFoundError("Upvote author not found")

        if not author == current_user.active_persona:
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
            jobs.refresh_upvote_count.delay(self.id)

            if upvote.state == 0 and \
                isinstance(self.mindset, context.Mindspace) and \
                    isinstance(self.mindset.author, context.Movement):

                jobs.check_promotion.delay(self.id)
            return upvote


class PerceptAssociation(Model):
    """Associates Percepts with Thoughts, defining an author for the connection"""

    __tablename__ = 'percept_association'

    percept_id = Column(String(32), ForeignKey('percept.id'), primary_key=True)
    thought_id = Column(String(32), ForeignKey('thought.id'), primary_key=True)

    author_id = Column(String(32), ForeignKey('identity.id'))
    author = relationship("Identity", backref="percept_assocs", lazy="joined")
    percept = relationship("Percept", backref="thought_assocs", lazy="joined")

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


class Percept(Model):
    """A Percept represents an attachment"""

    __tablename__ = 'percept'

    __mapper_args__ = {
        'polymorphic_identity': 'percept',
        'polymorphic_on': "kind"
    }

    id = Column(String(32), primary_key=True)

    created = Column(DateTime(), default=datetime.datetime.utcnow())
    kind = Column(String(32))
    modified = Column(DateTime(), default=datetime.datetime.utcnow())
    source = Column(String(128))
    state = Column(Integer(), default=0)
    title = Column(Text)

    def __repr__(self):
        return "<Percept:{} [{}]>".format(self.kind, self.id[:6])


class Tag(Model):

    __tablename__ = "tag"

    id = Column(String(32), primary_key=True)

    name = Column(String(32))

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

    __tablename__ = 'tag_percept'

    id = db.Column(db.String(32), db.ForeignKey('percept.id'), primary_key=True)

    # Relations
    tag_id = Column(String(32), ForeignKey('tag.id'))
    tag = relationship('Tag', backref="synonyms")

    def __init__(self, *args, **kwargs):
        Percept.__init__(self, *args, **kwargs)
        self.id = uuid4().hex
        self.tag = Tag.get_or_create(kwargs["title"])

    def __repr__(self):
        return "<#{} (#{}) [{}]>".format(self.title, self.tag.name, self.id[:6])

    __mapper_args__ = {
        'polymorphic_identity': 'tag'
    }


class Mention(Percept):
    """Mention an Identity to notify them"""

    __tablename__ = 'mention'

    id = db.Column(db.String(32), db.ForeignKey('percept.id'), primary_key=True)

    text = Column(String(80))
    identity_id = Column(String(32), ForeignKey('identity.id'))
    identity = relationship('Identity', backref="mentions")

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

    __mapper_args__ = {
        'polymorphic_identity': 'mention'
    }


class LinkedPicturePercept(Percept):
    """A linked picture attachment"""

    __tablename__ = 'linked_picture_percept'

    __mapper_args__ = {
        'polymorphic_identity': 'linkedpicture'
    }

    id = db.Column(db.String(32), db.ForeignKey('percept.id'), primary_key=True)

    url = Column(Text)

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


class LinkPercept(Percept):
    """A URL attachment"""

    __tablename__ = 'link_percept'

    __mapper_args__ = {
        'polymorphic_identity': 'link'
    }

    id = db.Column(db.String(32), db.ForeignKey('percept.id'), primary_key=True)

    url = Column(Text)

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


class TextPercept(Percept):
    """A longform text attachment"""

    __tablename__ = 'text_percept'

    __mapper_args__ = {
        'polymorphic_identity': 'text'
    }

    id = db.Column(db.String(32), db.ForeignKey('percept.id'), primary_key=True)

    text = Column(Text)

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


class Upvote(Thought):
    """A Upvote is a vote that signals interest in its parent Thought"""

    __mapper_args__ = {
        'polymorphic_identity': 'upvote'
    }

    def __repr__(self):
        if ["author_id", "parent_id"] in dir(self):
            return "<Upvote <Persona {}> -> <Thought {}> ({})>".format(
                self.author_id[:6], self.parent_id[:6], self.get_state())
        else:
            return "<Upvote ({})>".format(self.get_state())

    def hot(self):
        return 0


class Notification(Model):
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

    id = Column(Integer(), primary_key=True)

    created = Column(DateTime(), default=datetime.datetime.utcnow())
    domain = Column(String(128))
    modified = Column(DateTime(), default=datetime.datetime.utcnow())
    source = Column(String(128))
    text = Column(Text)
    unread = Column(Boolean(), default=True)
    url = Column(Text, default="/")

    # Set this to the name of the attribute on User model (that is, the email
    # preference) that determines whether the notification sends emails
    email_pref = None

    # Relations
    recipient = relationship('Identity',
        backref=backref('notifications', lazy="dynamic"))
    recipient_id = Column(String(32), ForeignKey('identity.id'))

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
