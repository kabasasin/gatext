from typing import Callable, List

from gatex.parser.stack import CONTENT_STACK, TAG_STACK, NO_STEP_REG, NO_SAVE_REG, SPACE_EAT_REG, FORCE_SAVE_REG
# from gatex.parser.symbol import is_tag_start, is_tag_end
# from gatex.parser.symbol import TAG_START_SYMBOL, TAG_NAME, TAG_END_SYMBOL
from gatex.parser.symbol import *


class Scanner(object):
    def __init__(self):
        self.file = None

    def load_file(self, file_name):
        self.file = open(file_name)

    def eat(self):
        # finite set of input symbols Σ
        if NO_STEP_REG.get():
            NO_STEP_REG.set(False)
            return
        c = self.file.read(1)
        if not c:
            CONTENT_STACK.push(chr(0))
        else:
            CONTENT_STACK.push(c)

    def match(self):
        dfa = Parse(StartState(), self.eat)
        dfa.run()
        block_count = 0
        for state in dfa.transit_list:
            if isinstance(state, BlockEnd):
                block_count -= 1
            if isinstance(state, (Mark, TagStart, TagReadName, TagEnd)):
                print("  " * block_count, state, end=" ")
            else:
                print("  " * block_count, state)
            if isinstance(state, BlockStart):
                block_count += 1


class State(object):
    # finite set of `states` (Q)
    name = "EMPTY"

    def __init__(self):
        self.content = ""

    def transit(self) -> object:
        # transition `function` δ: Q x Σ -> Q
        return self

    def __repr__(self):
        return "{}: {}".format(self.name, repr(self.content))


class StopState(State):
    name = "STOP"

    def transit(self):
        self.content = "STOP"
        if CONTENT_STACK.content != "":
            raise Exception("parser failed: {}".format(CONTENT_STACK.content))
        return None


class StartState(State):
    # initial or start state q0
    name = "Start"

    def transit(self) -> State:
        self.content = "START"
        NO_SAVE_REG.set(True)
        return Content()


class Content(State):
    name = "Content"
    tag = True
    mark = True
    block_end = True

    # possible = False

    def transit(self) -> State:
        if CONTENT_STACK.content == chr(0):
            # NO_SAVE_REG.set(True)
            CONTENT_STACK.pop_all()
            return StopState()
        # TAG or Mark
        if self.tag:
            res, reason = is_tag_start(CONTENT_STACK.content)
            # match tag start symbol
            if res:
                NO_STEP_REG.set(True)
                return TagStart()
            else:
                # too lang for tag start
                if reason in [OVER_MAX_LENGTH, NOT_MATCH]:
                    self.tag = False
                # not match this time: try mark or eat more rune
                elif reason == POSSIBLE:
                    self.tag = True
                else:
                    return StopState()
        if self.mark:
            res, reason = is_mark(CONTENT_STACK.content)
            if res:
                NO_STEP_REG.set(True)
                # match tag start symbol
                return Mark()
            else:
                # too lang for MARK
                if reason in [OVER_MAX_LENGTH, NOT_MATCH]:
                    self.mark = False
                # not match this time: eat more rune
                elif reason == POSSIBLE:
                    self.mark = True
                else:
                    return StopState()
        if self.block_end:
            res, reason = is_block_end(CONTENT_STACK.content)
            if res:
                NO_STEP_REG.set(True)
                return BlockEnd()
            else:
                if reason in [OVER_MAX_LENGTH, NOT_MATCH]:
                    self.block_end = False
                elif reason == POSSIBLE:
                    self.block_end = True
                else:
                    return StopState()
        if True in [self.tag, self.mark, self.block_end]:
            NO_SAVE_REG.set(True)
            return self
        # not tag or mark
        # other contents
        self.content += CONTENT_STACK.pop_all()
        self.tag = True
        self.mark = True
        self.block_end = True
        return self


class Mark(State):
    name = "Mark"
    """
    Mark -> Content
    Mark -> Block
    """

    def transit(self) -> State:
        self.content = CONTENT_STACK.pop_all()
        NO_SAVE_REG.set(True)
        SPACE_EAT_REG.set(True)
        FORCE_SAVE_REG.set(True)
        return BlockStart()


class TagStart(State):
    name = "TagStart"

    def transit(self) -> State:
        self.content = CONTENT_STACK.pop_all()
        TAG_STACK.append(self.content)
        return TagReadName()


class TagReadName(State):
    name = "Tag"

    def transit(self) -> State:
        res, reason = is_tag_name(CONTENT_STACK.content)
        if res:
            self.content = CONTENT_STACK.pop_all()
            return TagEnd()
        else:
            if reason in [OVER_MAX_LENGTH, NOT_MATCH]:
                return StopState()
            elif reason == POSSIBLE:
                return self
            else:
                return StopState()


class TagEnd(State):
    name = "TagEnd"
    """
    Tag -> Content
    Tag -> Block
    """

    def transit(self) -> State:
        res, reason = is_tag_end(CONTENT_STACK.content)
        if res:
            if TAG_STACK[-1] != CONTENT_STACK.content:
                return StopState()
            else:
                self.content = CONTENT_STACK.pop_all()
                TAG_STACK.pop(-1)
                NO_SAVE_REG.set(True)
                SPACE_EAT_REG.set(True)
                return BlockStart()
        else:
            if reason in [OVER_MAX_LENGTH, NOT_MATCH]:
                return StopState()
            elif reason == POSSIBLE:
                NO_SAVE_REG.set(True)
                return self
            else:
                return StopState()


class BlockStart(State):
    name = "BlockStart"

    def transit(self) -> State:
        res, reason = is_block_start(CONTENT_STACK.content)
        if res:
            self.content = CONTENT_STACK.pop_all()
            TAG_STACK.append(self.content)
            FORCE_SAVE_REG.set(True)
            return Content()
        else:
            if reason in [OVER_MAX_LENGTH, NOT_MATCH]:
                NO_SAVE_REG.set(True)
                NO_STEP_REG.set(True)
                return Content()
            elif reason == POSSIBLE:
                # NO_SAVE_REG.set(True)
                return self
            else:
                return StopState()


class BlockEnd(State):
    name = "BlockEnd"

    def transit(self) -> State:
        self.content = CONTENT_STACK.pop_all()
        TAG_STACK.pop(-1)
        return Content()


class Parse(object):
    # DFA
    def __init__(self, state: State, eat: Callable):
        # initial `state` q0
        self.init = state
        self.last = None
        self.current = self.init
        self.eat_function = eat

        self.transit_list: List[State] = []
        self.transit_list.append(self.init)

    def run(self):
        while True:
            self.last = self.current
            self.current = self.current.transit()
            if self.current.name == "STOP":
                self.current.transit()
                self.save()
                return
            self.save()
            self.eat_function()
            # eat space
            if SPACE_EAT_REG.get():
                while True:
                    if CONTENT_STACK.content == " ":
                        CONTENT_STACK.pop()
                        self.eat_function()
                    else:
                        SPACE_EAT_REG.set(False)
                        break

    def save(self):
        # TODO BUILD AST
        if NO_SAVE_REG.get():
            NO_SAVE_REG.set(False)
            return
        if FORCE_SAVE_REG.get():
            self.transit_list.append(self.last)
            FORCE_SAVE_REG.set(False)
        if self.transit_list[-1].name != self.current.name:
            self.transit_list.append(self.current)
