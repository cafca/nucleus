import logging
import blinker
import time

UPVOTE_CACHE_DURATION = 60 * 10

ATTENTION_CACHE_DURATION = 60 * 10

TOP_MOVEMENT_CACHE_DURATION = 60 * 60
MEMBER_COUNT_CACHE_DURATION = 60 * 60
REPOST_MINDSET_CACHE_DURATION = 60 * 60 * 24

TOP_THOUGHT_CACHE_DURATION = 60 * 60
RECENT_THOUGHT_CACHE_DURATION = 60 * 60 * 24
MINDSPACE_TOP_THOUGHT_CACHE_DURATION = 60 * 10

SUGGESTED_MOVEMENTS_CACHE_DURATION = 60 * 10
PERSONA_MOVEMENTS_CACHE_DURATION = 60 * 10
CONVERSATION_LIST_CACHE_DURATION = 60 * 60 * 24

IFRAME_URL_CACHE_DURATION = 24 * 60 * 60

ATTENTION_MULT = 10

# Setup logger namespace
logger = logging.getLogger('nucleus')

# Setup Blinker namespace
notification_signals = blinker.Namespace()
movement_chat = notification_signals.signal('movement-chat')

ALLOWED_COLORS = {
    '0b3954': "Base blue",
    'c81d25': "Accent red",
    '71a2b6': "Quiet blue",
    'f5cb5c': "Yellow",
    '8bb174': "Green",
    '129490': "Turquiousuioso",
    'ef3054': "Bright pink"
}

ACCESS_MODES = ("insert", "read", "update", "delete")

ATTACHMENT_KINDS = ("link", "linkedpicture", "text")


class ExecutionTimer(object):
    def __init__(self):
        self.start = time.clock()

    def stop(self, msg):
        end = (time.clock() - self.start) * 1000.0
        logger.debug("{} in {} ms".format(msg, end))


class PersonaNotFoundError(Exception):
    """Throw this error when the Persona profile specified for an action is not available"""
    pass


class UnauthorizedError(Exception):
    """Throw this error when the active Persona is not authorized for an action"""
    pass
