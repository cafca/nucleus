import os
import os.path
import sys
import pytest
import redis
import datetime
import logging

# This directory will not be added to PYTHONPATH by py.test when run here
# because its parent dir is a module
sys.path.append(os.path.join(os.getcwd(), '..'))

from rq import Queue

from glia import create_app
from nucleus import make_key
from nucleus.connections import db as _db
from nucleus.content import Thought, ReplyNotification, \
    MentionNotification, Mention, DialogueNotification, FollowerNotification
from nucleus.identity import User, Persona, Movement
from nucleus.context import Mindspace, Blog, Mindset


@pytest.fixture(scope="session")
def app(request):
    """Provide glia app context to tests"""

    settings_override = {
        'TESTING': True,
        # 'SQLALCHEMY_DATABASE_URI': "postgresql://localhost/glia_test"
        'SQLALCHEMY_DATABASE_URI': "sqlite://",
        'CACHE_TYPE': "null"
    }

    app = create_app(__name__, settings_override)

    # Establish an application context before running the tests.
    ctx = app.app_context()
    ctx.push()

    def teardown():
        ctx.pop()

        # Remove Redis jobs
        redis_url = os.getenv('REDISTOGO_URL', 'redis://localhost:6379')
        conn = redis.from_url(redis_url)
        for l in ['high', 'default', 'low']:
            Queue(l, connection=conn).empty()

    request.addfinalizer(teardown)
    return app


@pytest.fixture(scope='session')
def db(app, request):
    """Session-wide test database."""
    def teardown():
        _db.drop_all()

    _db.create_all()

    request.addfinalizer(teardown)
    return _db


@pytest.fixture(scope='function', autouse=True)
def session(db, request):
    """Creates a new database session for a test."""
    connection = db.engine.connect()
    transaction = connection.begin()

    options = dict(bind=connection, binds={})
    session = db.create_scoped_session(options=options)

    db.session = session

    def teardown():
        transaction.rollback()
        connection.close()
        session.remove()

    request.addfinalizer(teardown)
    return session

#
# Identity
#


@pytest.fixture(scope="function")
def persona(session, request):
    created_dt = datetime.datetime.utcnow()
    ident = make_key()
    persona = Persona(
        id=ident,
        username="Alice-{}".format(ident[:2]),
        created=created_dt,
        modified=created_dt,
        color="0b3954")

    persona.mindspace = Mindspace(
        id=make_key(),
        author=persona)

    persona.blog = Blog(
        id=make_key(),
        author=persona)

    session.add(persona)
    session.commit()
    return persona


@pytest.fixture(scope="function")
def personas(session, request):
    rv = []
    for i in range(2):
        rv.append(persona(session, request))
    return rv


@pytest.fixture(scope="function")
def user(session, personas, request):
    created_dt = datetime.datetime.utcnow()
    ident = make_key()

    user = User(
        id=ident,
        email="test-{}@gmail.com".format(ident[:2]),
        active_persona=personas[0],
        created=created_dt,
        modified=created_dt)
    user.set_password("test")

    for persona in personas:
        persona.user = user

    session.add(user)
    session.commit()

    return user


@pytest.fixture(scope="function")
def movements(session, request, personas):
    rv = []
    for i in range(2):
        created_dt = datetime.datetime.utcnow()
        ident = make_key()
        movement = Movement(
            id=ident,
            username="Movement-{}".format(ident[:2]),
            description="Doin' good",
            created=created_dt,
            modified=created_dt,
            color="0b3954",
            admin=personas[i])

        personas[i].toggle_movement_membership(movement, role="admin")

        session.add(movement)
        session.commit()
        rv.append(movement)

    for obj in rv:
        session.add(obj)
    session.commit()
    logging.warning("Generated {} in {}".format(rv, session))
    return rv


@pytest.fixture(scope="function")
def movement_with_thoughts(session, movements, thoughts):
    for t in thoughts:
        t.mindset = movements[0].mindspace
        session.add(t)
    session.commit()
    return movements[0]


#
# Content fixtures
#


@pytest.fixture(scope="function")
def thoughts(personas, session):
    """Return two thoughts for each of two authors"""
    rv = []
    for persona in personas:
        created_dt = datetime.datetime.utcnow()
        ident = make_key()
        t1 = Thought(
            id=ident,
            created=created_dt,
            text=ident[:6],
            author=persona
        )
        rv.append(t1)

        ident = make_key()
        created_dt = datetime.datetime.utcnow()
        t2 = Thought(
            id=ident,
            created=created_dt,
            text=ident[:6],
            author=persona,
            parent=t1
        )
        rv.append(t2)

    for obj in rv:
        session.add(obj)
    session.commit()
    return rv


@pytest.fixture(scope="function")
def thought_with_attachments(personas, session):
    teststring = """Ok, so this is my #test for @{username}
    I have an image http://i.imgur.com/Yzv9H.jpg

    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam bibendum lobortis urna eu hendrerit. In hac habitasse platea dictumst. Etiam vestibulum, dui ut congue eleifend, nisi sapien commodo dolor, et interdum velit turpis vel odio. Duis interdum quis erat in elementum. Mauris vitae enim ac turpis pulvinar iaculis. Nam nec lorem sit amet sem hendrerit porta ut aliquet urna. Aenean non vehicula ante, et tincidunt mi. Morbi pellentesque lobortis nulla at viverra. Maecenas rutrum quam vitae turpis eleifend convallis.

Etiam sit amet eleifend erat. Praesent tincidunt vestibulum risus posuere lobortis. Nulla feugiat elit metus, non rhoncus ex tempor non. Aliquam erat volutpat. Etiam ut pellentesque lacus, ut ullamcorper dolor. Ut commodo malesuada leo a pharetra. Suspendisse potenti. Aliquam faucibus est nec tortor aliquam, in luctus mi cursus.

Cras volutpat a dui non ultricies. Mauris in dolor luctus mi mattis tincidunt ac commodo lacus. Duis convallis eu metus sit amet vestibulum. Cras est magna, consequat tincidunt nulla eu, viverra elementum risus. Suspendisse laoreet tempus turpis at fringilla. Quisque id turpis ut augue dapibus semper. Morbi vel purus nec augue pellentesque iaculis eu vel neque. Quisque ac libero at erat pellentesque lobortis sit amet id ante. Duis eu ante nec eros eleifend tempor ut et lectus. Etiam faucibus ante elementum, maximus quam at, condimentum lacus. Integer fringilla, nunc nec euismod accumsan, ligula enim iaculis nulla, vitae lobortis sem elit vel mi. Fusce vehicula faucibus nisl, eget rutrum lorem lobortis nec. Sed odio mi, fringilla eu finibus vel, cursus in augue. Duis ac diam velit. Suspendisse molestie eu lacus sit amet suscipit. Nam sagittis mauris vitae est feugiat, egestas venenatis ex congue.

    and a link http://i.imgur.com/Yzv9H/
    """.format(username=personas[1].username)

    thought_data = Thought.create_from_input(
        author=personas[0],
        text="Test title",
        longform=teststring,
        longform_source="source",
        mindset=personas[0].blog)

    return thought_data["instance"]


@pytest.fixture(scope="function")
def notifications(personas, thoughts, session):
    rv = []

    url = "http://about:blank"

    mention = Mention(
        id=make_key(),
        text="test mention notification",
        identity=personas[0])

    rv.append(MentionNotification(mention, personas[0], url))
    rv.append(ReplyNotification(thoughts[0], personas[0], url))
    rv.append(DialogueNotification(personas[0], personas[1]))
    rv.append(FollowerNotification(personas[0], personas[1]))

    for obj in rv:
        session.add(obj)
    session.commit()

    return rv

#
# Context
#


@pytest.fixture
def mindset(personas, thoughts, session):
    ms = Mindset(
        id=make_key(),
        modified=datetime.datetime.utcnow(),
        author=personas[0]
    )

    ms.index.extend(thoughts)

    session.add(ms)
    session.commit()
    return ms
