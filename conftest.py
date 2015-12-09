import os
import os.path
import sys
import pytest

# This directory will not be added to PYTHONPATH by py.test when run here
# because its parent dir is a module
sys.path.append(os.path.join(os.getcwd(), '.'))
sys.path.append(os.path.join(os.getcwd(), '..'))

from glia import create_app


@pytest.fixture()
def app(request):
    """Provide glia app context to tests"""

    settings_override = {
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': "postgresql://localhost/glia_dev"
    }

    app = create_app(__name__, settings_override)

    # Establish an application context before running the tests.
    ctx = app.app_context()
    ctx.push()

    def teardown():
        ctx.pop()

    request.addfinalizer(teardown)
    return app
