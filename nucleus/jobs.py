# -*- coding: utf-8 -*-
"""
    nucleus.jobs
    ~~~~~

    Collection of functions for performing time consuming tasks

    :copyright: (c) 2013 by Vincent Ahrend.
"""
import logging

import content
import context
import identity

from flask.ext.rq import job

from .connections import cache, session_scope
from .helpers import recent_thoughts

logger = logging.getLogger('nucleus')

# These function names will be called in the specified (seconds) interval
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
    from glia import create_app
    app = create_app(log_info=False)
    with app.app_context():
        with session_scope() as session:
            logger.info("Refreshing attention cache")

            for ident in session.query(identity.Identity).all():
                cache.delete_memoized(ident.get_attention)
                ident.get_attention(session=session)


@job
def refresh_conversation_lists(dialogue_id):
    """Refresh conversation list cache for all participants in a given dialogue"""
    from glia import create_app
    app = create_app(log_info=False)
    with app.app_context():
        with session_scope() as session:
            dialogue = session.query(context.Dialogue).get(dialogue_id)

            if dialogue and isinstance(dialogue, context.Dialogue):
                logger.info("Refreshing conversation list cache for all parties in {}"
                    .format(dialogue))
                cache.delete_memoized(dialogue.author.conversation_list)
                cache.delete_memoized(dialogue.other.conversation_list)

                dialogue.author.conversation_list()
                dialogue.other.conversation_list()


@job
def refresh_frontpages():
    from glia import create_app
    app = create_app(log_info=False)
    with app.app_context():
        with session_scope() as session:
            from glia.web.helpers import generate_graph
            logger.info("Refreshing frontpages")

            content.Thought.top_thought()

            for p in session.query(identity.Persona).all():
                frontpage = session.query(content.Thought).filter(content.Thought.id.in_(
                    content.Thought.top_thought(persona=p, filter_blogged=True, session=session)))
                logging.info(frontpage)
                generate_graph(persona=p, session=session)


@job
def refresh_mindspace_top_thought():
    from glia import create_app
    app = create_app(log_info=False)
    with app.app_context():
        with session_scope() as session:
            logger.info("Refreshing movement mindspaces")
            for movement in session.query(identity.Movement).all():
                cache.delete_memoized(movement.mindspace_top_thought)
                movement.mindspace_top_thought(session=session)


@job
def refresh_recent_thoughts():
    """Refresh cache of recent thoughts"""
    from glia import create_app
    app = create_app(log_info=False)
    with app.app_context():
        with session_scope() as session:
            cache.delete_memoized(recent_thoughts)
            return recent_thoughts(session=session)


@job
def refresh_upvote_count(thought_id):
    """Recalculate upvote count"""
    from glia import create_app
    app = create_app(log_info=False)
    with app.app_context():
        with session_scope() as session:
            thought = session.query(content.Thought).get(thought_id)
            cache.delete_memoized(thought.upvote_count)
            return thought.upvote_count(session=session)


@job
def check_promotion(thought_id):
    """Check whether a thought has passed promotion threshold"""
    from glia import create_app
    app = create_app(log_info=False)
    with app.app_context():
        with session_scope() as session:
            thought = session.query(content.Thought).get(thought_id)

            movement = thought.mindset.author
            passed = movement.promotion_check(thought, session=session)

            if passed:
                session.add(movement.blog)
                session.commit()

                cache.delete_memoized(movement.mindspace_top_thought)
