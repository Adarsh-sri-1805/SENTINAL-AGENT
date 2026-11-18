"""Document retriever for the OmniCorp knowledge base."""

import re
from typing import List, Tuple
from app.fixtures.knowledge_base import KBArticle, get_knowledge_base


def _tokenize(text: str) -> set[str]:
    """Extract lowercase alphanumeric tokens."""
    return set(re.findall(r"\w+", text.lower()))


def score_article(query_tokens: set[str], article: KBArticle) -> float:
    """Compute simple term-overlap relevance score."""
    if not query_tokens:
        return 0.0

    title_tokens = _tokenize(article.title)
    tag_tokens = set(t.lower() for t in article.tags)
    content_tokens = _tokenize(article.content)

    score = 0.0
    for token in query_tokens:
        # Title matches carry higher weight
        if token in title_tokens:
            score += 3.0
        # Tag matches carry medium weight
        if token in tag_tokens:
            score += 2.0
        # Content matches carry standard weight
        if token in content_tokens:
            score += 1.0

    return score


def retrieve_documents(
    query: str,
    mode: str = "vulnerable",
    limit: int = 3,
) -> List[Tuple[KBArticle, float]]:
    """Retrieve top relevant knowledge base articles for a query.

    In 'protected' mode: strictly filters out 'internal', 'customer', and 'confidential' records.
    In 'vulnerable' mode: searches across all categories without access controls.

    Args:
        query: User query string.
        mode: Active security mode ('vulnerable' or 'protected').
        limit: Maximum number of articles to return.

    Returns:
        List[Tuple[KBArticle, float]]: List of (article, score) pairs.
    """
    all_articles = get_knowledge_base()
    query_tokens = _tokenize(query)

    # Filter candidate pool based on security mode
    if mode == "protected":
        candidates = [a for a in all_articles if a.category == "public"]
    else:
        # Vulnerable mode allows retrieval across all categories (public, customer, internal, confidential)
        candidates = all_articles

    scored: List[Tuple[KBArticle, float]] = []
    for article in candidates:
        s = score_article(query_tokens, article)
        # Even if score is 0, include public docs if query is generic, or filter to s > 0
        if s > 0:
            scored.append((article, s))

    # Sort descending by score
    scored.sort(key=lambda x: x[1], reverse=True)

    # If no keyword matches found, return default public policy in protected mode, or top docs
    if not scored:
        default_pool = [a for a in candidates if a.category == "public"] or candidates
        return [(a, 0.1) for a in default_pool[:limit]]

    return scored[:limit]

