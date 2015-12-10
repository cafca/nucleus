# -*- coding: utf-8 -*-
"""
    nucleus.tests.test_identity
    ~~~~~

    Test identity models

    :copyright: (c) 2015 by Vincent Ahrend.
"""
import datetime

from nucleus.nucleus import make_key
from nucleus.nucleus.identity import Identity, Movement
from nucleus.nucleus.content import Thought, ReplyNotification
from nucleus.nucleus.context import Dialogue

#
# Tests for models
#


class TestUser:
    def test_persona_association(self, user):
        assert user == user.associations[0].user

    def test_password(self, user):
        assert user.check_password("test")
        user.set_password('test-1')
        assert not user.check_password("test")
        assert user.check_password("test-1")

    def test_email_allowed(self, user):
        t = Thought(
            id=make_key(),
            text="test",
            author=user.active_persona
        )
        notif = ReplyNotification(t, user.active_persona, "http://lol")
        assert user.email_allowed(notif)

    def test_user_anonymous(self, user):
        assert user.is_anonymous() is False

    def test_validation_status(self, user):
        assert not user.validated
        user.validate()
        assert user.validated

    def test_signup_code(self, user):
        assert not user.valid_signup_code("")
        assert user.valid_signup_code(user.signup_code)

        # Test expiration
        user.created = datetime.datetime.utcnow() - datetime.timedelta(days=10)
        assert not user.valid_signup_code(user.signup_code)


class TestIdentity():
    def test_authorize(self, personas):
        # Everyone can see identity profils
        assert Identity.authorize(personas[0], "read", author_id=personas[0].id)
        assert Identity.authorize(personas[0], "read", author_id=personas[1].id)

        # But they can only change them thmselves
        assert Identity.authorize(personas[0], "update", author_id=personas[0].id)
        assert not Identity.authorize(personas[0], "update", author_id=personas[1].id)

    def test_notification_list(self, notifications):
        persona = notifications[0].recipient
        assert len(persona.notification_list()) > 0


class TestPersona():
    def test_repr(self, persona):
        assert len(persona.__repr__()) > 0

    def test_attention(self, thoughts):
        persona = thoughts[0].author
        assert isinstance(persona.get_attention(), int)

    def test_conversation_list(self, thoughts, session):
        personas = list(set(t.author for t in thoughts))

        assert len(personas[0].conversation_list()) == 0

        d = Dialogue(
            id=make_key(),
            author=personas[0],
            other=personas[1])

        assert len(personas[0].conversation_list()) == 0

        map(d.index.append, thoughts)
        session.add(d)
        session.commit()

        assert len(personas[0].conversation_list()) > 0

    def test_follow_top_movements(self, persona, movements, session):
        persona.follow_top_movements(session=session)

        session.add(persona)
        session.commit()

        assert len(persona.blogs_followed) > 0

    def test_frontpage_sources(self, persona, movements, session):
        print "test_frontpage_sources session", session
        persona.follow_top_movements(session=session)

        session.add(persona)
        session.commit()

        fps = persona.frontpage_sources()
        assert len(fps) > 0
        assert isinstance(fps[0], basestring)

    def test_absolute_url(self, persona):
        assert persona.get_absolute_url().startswith("http")

    def test_movement_list(self, movements):
        assert len(movements[0].admin.movements()) > 0

    def test_repost_mindsets(self, movements):
        assert len(movements[0].admin.repost_mindsets()) >= 3

    def test_suggested_movements(self, movements, session):
        p = movements[0].admin
        suggestions = p.suggested_movements()
        assert len(suggestions) > 0
        assert isinstance(suggestions[0], basestring)
        movements = session.query(Movement).filter(Movement.id.in_(suggestions))
        for m in movements:
            assert not m.active_member(persona=p, session=session)

    def test_toggle_following(self, personas):
        personas[0].toggle_following(personas[1])
        assert personas[1] in personas[0].blogs_followed
        personas[0].toggle_following(personas[1])
        assert personas[1] not in personas[0].blogs_followed


class TestMovement():
    def test_top_movements(self, movements):
        assert len(Movement.top_movements()) > 0
