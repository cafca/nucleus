# -*- coding: utf-8 -*-
"""
    nucleus.tests.test_identity
    ~~~~~

    Test identity models

    :copyright: (c) 2015 by Vincent Ahrend.
"""
import datetime

from nucleus.nucleus import make_key
from nucleus.nucleus.identity import Identity
from nucleus.nucleus.content import Thought, ReplyNotification

#
# Tests for models
#


class TestUser:
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
