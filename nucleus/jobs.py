# -*- coding: utf-8 -*-
"""
    glia.jobs
    ~~~~~

    Collection of functions for performing time consuming tasks

    :copyright: (c) 2013 by Vincent Ahrend.
"""
import logging

from flask.ext.rq import job

from .connections import cache
from .helpers import recent_thoughts

logger = logging.getLogger('nucleus')


@job
def refresh_conversation_lists(dialogue_id):
    """Refresh conversation list cache for all participants in a given dialogue"""
    from .models import Dialogue

    rv = None

    dialogue = Dialogue.query.get(dialogue_id)

    if dialogue and isinstance(dialogue, Dialogue):
        logger.info("Deleting conversation list cache for all parties in {}"
            .format(dialogue))
        cache.delete_memoized(dialogue.author.conversation_list)
        cache.delete_memoized(dialogue.other.conversation_list)

        rv = dialogue.author.conversation_list()
        rv += dialogue.other.conversation_list()
    return rv


@job
def refresh_recent_thoughts():
    """Refresh cache of recent thoughts"""

    cache.delete_memoized(recent_thoughts)
    return recent_thoughts()
