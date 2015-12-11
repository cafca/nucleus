# -*- coding: utf-8 -*-
"""
    nucleus.tests.test_identity
    ~~~~~

    Test identity models

    :copyright: (c) 2015 by Vincent Ahrend.
"""
import datetime
import pytest

from sqlalchemy import inspect

from nucleus.nucleus import make_key, UnauthorizedError
from nucleus.nucleus.identity import Identity, Movement
from nucleus.nucleus.content import Thought, ReplyNotification
from nucleus.nucleus.context import Dialogue


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

    def test_toggle_membership(self, movements, session):
        p = movements[0].admin
        m = movements[1]

        # base case
        assert not m.active_member(persona=p, session=session)
        assert m not in p.blogs_followed

        # toggle membership
        session.add(p.toggle_movement_membership(m, session=session))
        session.commit()

        assert m.active_member(persona=p, session=session)
        assert m in p.blogs_followed

        # un-toggle membership
        session.add(p.toggle_movement_membership(m, session=session))
        session.commit()

        assert not m.active_member(persona=p, session=session)

    def test_toggle_membership_admin(self, movements, session):
        p = movements[0].admin
        m = movements[0]

        # admin cannot leave
        with pytest.raises(NotImplementedError) as excinfo:
            p.toggle_movement_membership(m, session=session)

        assert excinfo.value.message == "Admin can't leave the movement"

    def test_toggle_membership_private(self, movements, personas, session):
        p = movements[0].admin
        m = movements[1]

        m.private = True

        # enable membership without invitation
        with pytest.raises(UnauthorizedError):
            p.toggle_movement_membership(m, session=session)

        # enable membership with invitation
        inv = m.create_invitation()

        session.add(p.toggle_movement_membership(m,
            session=session, invitation_code=inv.invitation_code))
        session.commit()

        assert m.active_member(p, session=session)
        assert inspect(inv).deleted

        # leave group
        session.add(p.toggle_movement_membership(m, session=session))
        session.commit()

        assert not m.active_member(persona=p, session=session)

        # re-enable membership without invitation
        with pytest.raises(UnauthorizedError):
            p.toggle_movement_membership(m, session=session)

        # re-enable membership with invitation
        inv = m.create_invitation()
        session.add(p.toggle_movement_membership(m,
            session=session, invitation_code=inv.invitation_code))
        session.commit()

        assert m.active_member(p, session=session)

    def test_mma(self, movements, personas):
        inv = movements[0].create_invitation()
        assert isinstance(inv.__repr__(), basestring)
        inv.persona = personas[0]
        assert isinstance(inv.__repr__(), basestring)


class TestMovement():
    def test_repr(self, movements):
        movements[0].username = "¨å¨πø-movement"
        assert isinstance(movements[0].__repr__(), basestring)

    def test_active_member(self, movements, session):
        p1 = movements[0].admin
        p2 = movements[1].admin
        m = movements[0]

        assert m.active_member(persona=p1, session=session)
        assert not m.active_member(persona=p2, session=session)

    def test_attention(self, movement_with_thoughts):
        assert isinstance(movement_with_thoughts.get_attention(), int)

    def test_authorize(self, movements):
        movements[0].private = True
        p1 = movements[0].admin
        p2 = movements[1].admin

        assert movements[0].authorize("read", author_id=p1.id)
        assert not movements[0].authorize("read", author_id=p2.id)
        assert movements[1].authorize("read", author_id=p1.id)
        assert movements[1].authorize("read", author_id=p2.id)

        assert movements[0].authorize("update", author_id=p1.id)
        assert not movements[0].authorize("update", author_id=p2.id)

    def test_current_role(self, movements, session):
        # TODO: support testing with varying value of current_user
        assert movements[0].current_role(
            persona=movements[0].admin, session=session) == "anonymous"

    def test_get_absolute_url(self, movements):
        assert movements[0].get_absolute_url().startswith('http')

    def test_member_count(self, movements):
        assert movements[0].member_count() == 1

    def test_mindspace_top_thought(self, movement_with_thoughts, session):
        res = movement_with_thoughts.mindspace_top_thought()
        assert len(res) > 0
        assert isinstance(res[0], basestring)
        t1 = session.query(Thought).get(res[0])
        t2 = session.query(Thought).get(res[1])
        assert t1.hot(session=session) >= t2.hot(session=session)

    def test_promotion(self, movement_with_thoughts, session):
        m = movement_with_thoughts
        t = m.mindspace.index[0]

        res = m.promotion_check(t)
        assert res is None
        assert not t._blogged
        assert len(m.blog) == 0

        t.toggle_upvote(author_id=m.admin.id, session=session)
        res = m.promotion_check(t, session=session)

        assert isinstance(res, Thought)
        assert t._blogged
        assert res in m.blog

    def test_required_votes(self, movements):
        assert movements[0].required_votes() >= 1

    def test_top_movements(self, movements, session):
        assert len(Movement.top_movements(session=session)) > 0

    def test_valid_invitation_code(self, movements, session):
        assert movements[0].valid_invitation_code("", session=session)

        movements[0].private = True
        inv = movements[0].create_invitation()
        assert movements[0].valid_invitation_code(inv.invitation_code,
            session=session)
        assert not movements[0].valid_invitation_code("",
            session=session)

    def test_voting_done(self, movement_with_thoughts, session):
        m = movement_with_thoughts
        t = m.mindspace.index.first()

        assert m.voting_done(t, session=session) < 1

        t.toggle_upvote(author_id=m.admin.id, session=session)
        assert m.voting_done(t, session=session) == 1
