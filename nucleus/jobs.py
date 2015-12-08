# -*- coding: utf-8 -*-
"""
    nucleus.jobs
    ~~~~~

    Collection of functions for performing time consuming tasks

    :copyright: (c) 2013 by Vincent Ahrend.
"""
import logging

from flask.ext.rq import job

from .connections import db, cache
from .helpers import recent_thoughts

logger = logging.getLogger('nucleus')

periodical = [
    ("refresh_attention_cache", 60 * 15),
    ("refresh_mindspace_top_thought", 60 * 15),
    ("refresh_frontpages", 60 * 15),
]


def job_id(domain, name):
    return "-".join([domain, name])


@job
def refresh_attention_cache():
    """Calculate current attention for all known identities"""
    from .models import Identity

    logger.info("Refreshing attention cache")

    for ident in Identity.query.all():
        cache.delete_memoized(ident.get_attention)
        ident.get_attention()


@job
def refresh_conversation_lists(dialogue_id):
    """Refresh conversation list cache for all participants in a given dialogue"""
    from .models import Dialogue

    dialogue = Dialogue.query.get(dialogue_id)

    if dialogue and isinstance(dialogue, Dialogue):
        logger.info("Refreshing conversation list cache for all parties in {}"
            .format(dialogue))
        cache.delete_memoized(dialogue.author.conversation_list)
        cache.delete_memoized(dialogue.other.conversation_list)

        dialogue.author.conversation_list()
        dialogue.other.conversation_list()


@job
def refresh_frontpages():
    from glia.web.helpers import generate_graph
    from .models import Persona, Thought
    logger.info("Refreshing frontpages")

    Thought.top_thought(source="blog")

    for p in Persona.query.all():
        logger.debug("Refreshing frontpage of {}".format(p.username.encode("utf-8")))
        frontpage = Thought.query.filter(Thought.id.in_(
            Thought.top_thought(source=p.frontpage_sources(), filter_blogged=True)))
        logging.info(frontpage)
        generate_graph(frontpage, persona=p)


@job
def refresh_mindspace_top_thought():
    from .models import Movement

    logger.info("Refreshing movement mindspaces")
    for movement in Movement.query.all():
        cache.delete_memoized(movement.mindspace_top_thought)
        movement.mindspace_top_thought()


@job
def refresh_recent_thoughts():
    """Refresh cache of recent thoughts"""

    cache.delete_memoized(recent_thoughts)
    return recent_thoughts()


@job
def refresh_upvote_count(thought):
    """Recalculate upvote count"""
    cache.delete_memoized(thought.upvote_count)
    return thought.upvote_count()


@job
def check_promotion(thought):
    """Check whether a thought has passed promotion threshold"""
    db.session.refresh(thought)
    movement = thought.mindset.author
    passed = movement.promotion_check(thought)

    if passed:
        db.session.add(movement.blog)
        db.session.commit()

        cache.delete_memoized(movement.mindspace_top_thought)
