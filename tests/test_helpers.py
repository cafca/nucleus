# -*- coding: utf-8 -*-
"""
    nucleus.tests.test_helpers
    ~~~~~

    Test helper functions

    :copyright: (c) 2015 by Vincent Ahrend.
"""
import datetime

from nucleus.nucleus.helpers import epoch, epoch_seconds, find_links, \
    find_mentions, find_tags, process_attachments, recent_thoughts
from nucleus.nucleus.content import Mention, TagPercept, LinkPercept, \
    LinkedPicturePercept, Thought


def test_epoch():
    assert isinstance(epoch, datetime.datetime)
    assert epoch_seconds(epoch) < 0


def test_find_links():
    teststring = """
        What the.Heck! This is google.com or https://mail.google.com/.
        I don't want any.help with visiting my favorite websites
        www.go.oo.ooo.g.ll.e.com and reddit.com/r/spacedicks"""

    res = find_links(teststring)
    assert len(res[0]) == 4  # yes, there is 'any.help'
    assert len(res[1]) < len(teststring)


def test_find_mentions(persona, session):
    teststring = "Oh, hello @{}! You look like a clown today? my@email.com" \
        .format(persona.username)
    res = find_mentions(teststring, session=session)
    assert len(res) == 1
    assert res[0][0] == persona.username
    assert res[0][1] == persona


def test_find_tags():
    teststring1 = "#wat"
    teststring2 = "Lol #guys, what's up! #today #celebrating #lol"

    res = find_tags(teststring1)
    assert res[0][0] == "wat"
    assert res[1] == teststring1

    res = find_tags(teststring2)
    assert len(res[0]) == 4
    assert "guys" in res[0]
    assert res[1].endswith("!")


def test_process_attachments(persona, session):
    teststring = """Ok, so this is my #test for @{username}
    I have an image http://i.imgur.com/Yzv9H.jpg
    and a link http://i.imgur.com/Yzv9H/
    """.format(username=persona.username)

    res = process_attachments(teststring)

    assert isinstance(res[0], basestring)
    assert len(res[0]) > 0

    for kind in [Mention, TagPercept, LinkPercept, LinkedPicturePercept]:
        assert len([p for p in res[1] if isinstance(p, kind)]) == 1


def test_recent_thoughts(session, movement_with_thoughts):
    res = recent_thoughts(session=session)
    assert len(res) > 0
    t1 = session.query(Thought).get(res[0])
    t2 = session.query(Thought).get(res[1])
    assert t1.created > t2.created
