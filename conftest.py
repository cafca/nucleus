import os
import os.path
import sys
import pytest
import datetime
import logging

# This directory will not be added to PYTHONPATH by py.test when run here
# because its parent dir is a module
sys.path.append(os.path.join(os.getcwd(), '..'))

from glia import create_app
from nucleus.connections import db as _db
from nucleus import make_key
from nucleus.content import Thought, ReplyNotification, \
    MentionNotification, Mention
from nucleus.identity import User, Persona, Movement
from nucleus.context import Mindspace, Blog


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
    return rv


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

    for obj in rv:
        session.add(obj)
    session.commit()

    return rv
