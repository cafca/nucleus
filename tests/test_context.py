# -*- coding: utf-8 -*-
"""
    nucleus.tests.test_context
    ~~~~~

    Test context models

    :copyright: (c) 2015 by Vincent Ahrend.
"""
import datetime
import pytest

from nucleus.nucleus import ACCESS_MODES
from nucleus.nucleus.identity import Identity


class TestMindset:
    def test_model_props(self, mindset, thoughts):
        for t in thoughts:
            assert t in mindset

        assert len(mindset) == len(thoughts)
        assert isinstance(mindset.__repr__(), basestring)
        assert isinstance(mindset.author, Identity)
        assert mindset in mindset.author.mindsets
        assert isinstance(mindset.modified, datetime.datetime)
        assert mindset.state == 0
        assert isinstance(mindset.name, basestring)

    def test_authorize(self, personas, mindset):
        assert personas[1] != mindset.author

        assert mindset.authorize("read", author_id=personas[1].id)
        assert mindset.authorize("update", author_id=mindset.author.id)
        assert not mindset.authorize("update", author_id=personas[1].id)

    def test_url(self, mindset):
        with pytest.raises(NotImplementedError):
            mindset.get_absolute_url()


class TestMindspace:
    def test_authorize(self, movements, personas, session):
        mov = movements[0]
        p = personas[1]

        assert p != mov.admin
        assert p not in mov

        mov.private = False
        assert mov.blog.authorize("read", author_id=p.id)
        assert mov.blog.authorize("update", author_id=mov.admin.id)
        assert not mov.blog.authorize("update", author_id=p.id)

        mov.private = True
        for action in ACCESS_MODES:
            assert mov.mindspace.authorize(action,
                author_id=mov.admin.id,
                session=session)
            assert not mov.mindspace.authorize(action,
                author_id=p.id,
                session=session)


class TestBlog:
    pass


class TestDialogue:
    pass
