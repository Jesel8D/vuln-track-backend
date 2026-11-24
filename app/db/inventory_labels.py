"""Minimal label normalization, shared by analytics and exact inventory filters."""


def display_label(column: str) -> str:
    # column is always a trusted SQL expression from server code, never a request.
    return f"nullif(btrim(regexp_replace({column}, '[[:space:]]+', ' ', 'g')), '')"


def label_key(column: str) -> str:
    return f"lower({display_label(column)})"
