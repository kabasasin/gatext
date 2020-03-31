TAG_START_SYMBOL = ["\\"]
TAG_END_SYMBOL = ["\\ ", "\\"]

BLOCK_SYMBOL = [(" {", "}"), ("{", "}")]

MARK_SYMBOL = ["# ", "#", "* ", "*"]

TAG_NAME = ["TITTLE"]

OVER_MAX_LENGTH = "OVER_MAX_LENGTH"
NOT_MATCH = "NOT_MATCH"
POSSIBLE = "POSSIBLE"


# /TAG/
# ^
def is_tag_start(s: str) -> (bool, str):
    if not s:
        return False, NOT_MATCH
    if s in TAG_START_SYMBOL:
        return True, ""
    elif len(s) > len(sorted(TAG_START_SYMBOL, key=len)[-1]):
        return False, "OVER_MAX_LENGTH"
    else:
        s_length = len(s)
        if s_length >= 1:
            for sym in TAG_START_SYMBOL:
                if s[:s_length] == sym[:s_length]:
                    return False, POSSIBLE
        return False, NOT_MATCH


# /TAG/
#     ^
def is_tag_end(s: str):
    if s in TAG_END_SYMBOL:
        return True, ""
    elif len(s) > len(sorted(TAG_END_SYMBOL, key=len)[-1]):
        return False, OVER_MAX_LENGTH
    else:
        s_length = len(s)
        if s_length >= 1:
            for sym in TAG_END_SYMBOL:
                if s[:s_length] == sym[:s_length]:
                    return False, POSSIBLE
        return False, NOT_MATCH


# /TAG/
#  ^^^
def is_tag_name(s: str):
    if s in TAG_NAME:
        return True, ""
    elif len(s) > len(sorted(TAG_NAME, key=len)[-1]):
        return False, OVER_MAX_LENGTH
    else:
        s_length = len(s)
        if s_length >= 1:
            for sym in TAG_NAME:
                if s[:s_length] == sym[:s_length]:
                    return False, POSSIBLE
        return False, NOT_MATCH


# /TAG/ {
#       ^
def is_block_start(s: str):
    if len(s) > len(sorted(BLOCK_SYMBOL, key=lambda x: len(x[0]))[-1]):
        return False, "OVER_MAX_LENGTH"
    possible = False
    s_length = len(s)
    for sym in BLOCK_SYMBOL:
        if s == sym[0]:
            return True, ""
        if not possible:
            if s[:s_length] == sym[0][:s_length]:
                possible = True
    if possible:
        return False, POSSIBLE
    return False, "NOT_MATCH"


# /TAG/ { <content> }
#                   ^
def is_block_end(s: str):
    if len(s) > len(sorted(BLOCK_SYMBOL, key=lambda x: len(x[1]))[-1]):
        return False, "OVER_MAX_LENGTH"
    possible = False
    s_length = len(s)
    for sym in BLOCK_SYMBOL:
        if s == sym[1]:
            return True, ""
        if not possible:
            if s[:s_length] == sym[1][:s_length]:
                possible = True
    if possible:
        return False, POSSIBLE
    return False, "NOT_MATCH"


def block_closed_check(s: str) -> str:
    for sym in BLOCK_SYMBOL:
        if s == sym[1]:
            return sym[0]


# MARK *
#      ^
def is_mark(s: str):
    if s in MARK_SYMBOL:
        return True, ""
    elif len(s) > len(sorted(MARK_SYMBOL, key=len)[-1]):
        return False, "OVER_MAX_LENGTH"
    else:
        s_length = len(s)
        if s_length >= 1:
            for sym in MARK_SYMBOL:
                if s[:s_length] == sym[:s_length]:
                    return False, POSSIBLE
        return False, NOT_MATCH