import logging
import blinker

ERROR = {
    "MISSING_MESSAGE_TYPE": (1, "No message type found."),
    "MISSING_PAYLOAD": (2, "No data payload found."),
    "OBJECT_NOT_FOUND": lambda name: (3, "Object does not exist: ".format(name)),
    "MISSING_KEY": lambda name: (4, "Missing data for this request: {}".format(name)),
    "INVALID_SIGNATURE": (5, "Invalid signature."),
    "INVALID_SESSION": (6, "Session invalid. Please re-authenticate."),
    "DUPLICATE_ID": lambda id: (7, "Duplicate ID: {}".format(id)),
    "SOUMA_NOT_FOUND": lambda id: (8, "Souma not found: {}".format(id)),
    "MISSING_PARAMETER": lambda name: (9, "Missing HTTP parameter: {}".format(name)),
    "PROTOCOL_UNSUPPORTED": (10, "The request uses an unsupported protocol version"),
    "INVALID_VALUE": lambda name: (11, "The request contained an invalid value ({})".format(name))
}

# Setup Blinker namespace
notification_signals = blinker.Namespace()

# Setup logger namespace
logger = logging.getLogger('nucleus')

# Source formatting helper
source_format = lambda address: None if address is None else \
    "{host}:{port}".format(host=address[0], port=address[1])

percept_sort_rank = {
    "PicturePercept": 100,
    "LinkedPicturePercept": 200,
    "TextPercept": 400,
    "LinkPercept": 300
}

# Possible states of thoughts
THOUGHT_STATES = {
    -2: (-2, "deleted"),
    -1: (-1, "unavailable"),
    0: (0, "published"),
    1: (1, "draft"),
    2: (2, "private"),
    3: (3, "updating")
}

# Possible states of percepts
PERCEPT_STATES = {
    -1: (-1, "unavailable"),
    0: (0, "published"),
    1: (1, "private"),
    2: (2, "updating")
}

# Possible states of 1ups
ONEUP_STATES = {
    -1: "disabled",
    0: "active",
    1: "unknown author"
}

ALLOWED_COLORS = {
    '0b3954': "Base blue",
    'c81d25': "Accent red",
    '71a2b6': "Quiet blue",
    'f5cb5c': "Yellow",
    '8bb174': "Green",
    '129490': "Turquiousuioso",
    'ef3054': "Bright pink"
}

CHANGE_TYPES = ("insert", "update", "delete")

ATTACHMENT_KINDS = ("link", "linkedpicture", "picture", "text")


class InvalidSignatureError(Exception):
    """Throw this error when a signature fails authenticity checks"""
    pass


class PersonaNotFoundError(Exception):
    """Throw this error when the Persona profile specified for an action is not available"""
    pass


class UnauthorizedError(Exception):
    """Throw this error when the active Persona is not authorized for an action"""
    pass


class VesicleStateError(Exception):
    """Throw this error when a Vesicle's state does not allow for an action"""
    pass


# Import at bottom to avoid circular imports
# Import all models to allow querying db binds
# from .models import *
# from vesicle import Vesicle
