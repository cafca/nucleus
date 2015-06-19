import logging
import re

from datetime import datetime
from goose import Goose
from sqlalchemy import inspect


# For calculating scores
epoch = datetime.utcfromtimestamp(0)
epoch_seconds = lambda dt: (dt - epoch).total_seconds() - 1356048000

logger = logging.getLogger('nucleus')


def find_links(text):
    """Given a text, find all alive links inside

    Args:
        text(String): The input to parse

    Returns:
        tuple:
            list: List of response objects for found URLs
            str: Text with links removed if they occur at the end
    """
    import requests

    # Everything that looks remotely like a URL
    expr = "((?:https?://)?\S+\.\w{2,3}\S*)"
    rv = list()
    rejects = set()

    candidates = re.findall(expr, text)

    if candidates:
        for i, c in enumerate(candidates[::-1]):
            if c[:4] != "http":
                c_schemed = "".join(["http://", c])
            else:
                c_schemed = c

            if c_schemed not in rejects:
                logger.info("Testing potential link '{}' for availability".format(c_schemed))
                try:
                    res = requests.head(c_schemed, timeout=3.0)
                except (requests.exceptions.RequestException, ValueError), e:
                    logger.info("Not a suitable link ({})".format(e))
                    rejects.add(c_schemed)
                else:
                    if res and res.status_code < 400:
                        rv.append(res)
                        # Only remove link if it occurs at the end of text
                        if (text.index(c) + len(c)) == len(text.rstrip()):
                            text = text.replace(c, "")
                    else:
                        res = "No response object" if res is None else res
                        logger.info("Not a suitable link ({})\n{}".format(res, c_schemed))
    return (rv, text)


def find_tags(text):
    """Given some text, find tags of the form "#<tag> with 1-32 chars and no
        whitespace. Remove tags from text if they occur at the end and their
        removal doesn't make text empty.

    Args:
        text: input text

    Returns:
        tuple:
            iterable: list of found tags
            text: input text
    """

    expr = "#([\S]{1,32})"
    text_new = text

    rv = re.findall(expr, text)[::-1]
    for tag in rv:
        if(text_new.index(tag) + len(tag)) == len(text_new.rstrip()):
            text_new = text_new.replace("#{}".format(tag), "")

    return (rv, text_new) if len(text_new) > 0 else (rv, text)


def find_mentions(text):
    """Given some text, find mentioned Identities formatted as "@<username>

    Args:
        text: input text

    Returns:
        iterable: pairs of (mention_text, Identity_object)
    """
    from .models import Identity
    expr = "@([\S]{3,80})"
    rv = []

    res = re.findall(expr, text)
    for mention_text in res:
        ident = Identity.query.filter_by(username=mention_text).first()
        if ident is not None:
            rv.append((mention_text, ident))
        else:
            logger.warning("No ident found corresponding to mention \
                {}".format(mention_text))

    return rv


def process_attachments(text):
    """Given some text a user entered, extract all attachments
    hinted at and return user message plus a list of Percept objects.

    All trailing links in user message are removed. If, as a result of this,
    the message becomes empty, the first linked percept's page title is set as
    the new user message.

    Args:
        text (String): Message entered by user

    Return:
        Tuple
            0: Message with some attachment hints removed (URLs)
            1: List of Percept instances extracted from text
    """
    from .models import LinkPercept, LinkedPicturePercept, TextPercept, \
        TagPercept, Mention

    g = Goose()
    percepts = set()

    tags, text = find_tags(text)
    for tag in tags:
        tagpercept = TagPercept(title=tag)
        percepts.add(tagpercept)

    mentions = find_mentions(text)
    for mention_text, ident in mentions:
        mention = Mention(identity=ident, text=mention_text)
        percepts.add(mention)

    links, text = find_links(text)
    for link in links:
        if "content-type" in link.headers and link.headers["content-type"][:5] == "image":
            linkpercept = LinkedPicturePercept.get_or_create(link.url)

            # Use picture filename as user message if empty
            if len(text) == 0:
                text = link.url[(link.url.rfind('/') + 1):]
        else:
            linkpercept = LinkPercept.get_or_create(link.url)
            page = g.extract(url=link.url)

            # Add metadata if percept object is newly created
            if inspect(linkpercept).transient is True:
                linkpercept.title = page.title

            # Extract article contents as new Percept
            if len(page.cleaned_text) > 300:
                textpercept = TextPercept.get_or_create(page.cleaned_text)
                textpercept.source = link.url

                percepts.add(textpercept)

            if len(text) == 0:
                text = page.title
        percepts.add(linkpercept)

    return (text, percepts)
