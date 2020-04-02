from typing import Callable, List

from gatex.parser.stack import CONTENT_STACK, TAG_STACK, NO_STEP_REG, SPACE_EAT_REG, SAVE_REG
from gatex.parser.stack import Stack
# from gatex.parser.symbol import is_tag_start, is_tag_end
# from gatex.parser.symbol import TAG_START_SYMBOL, TAG_NAME, TAG_END_SYMBOL
from gatex.parser.symbol import *
from gatex.parser.ast import Tag


class Scanner(object):
    def __init__(self):
        self.file = None
        self.node_list = []

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
            print("  " * block_count, state)
            if isinstance(state, BlockStart):
                block_count += 1
        self.node_list = dfa.transit_list

    def ast_build(self):
        node_stack = []
        block_stack = []
        content_stack = []

        read_next_tag = False

        for index, node in enumerate(self.node_list):
            if isinstance(node, (TagReadName, Mark,)):
                node_stack.append(node)
            elif isinstance(node, (TagStart, TagEnd)):
                pass
            elif isinstance(node, BlockStart):
                pass
            elif isinstance(node, BlockEnd):
                pass
            elif isinstance(node, Content):
                if not node_stack:
                    # bare text
                    print(Tag(node_stack[-1].name, node.content))
                else:
                    pass
        # TODO DESIGN

    def tag_build(self):
        pass

    def block_build(self):
        pass


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
        # NO_SAVE_REG.set(True)
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
            return self
        # not tag or mark
        # other contents
        self.content += CONTENT_STACK.pop_all()
        self.tag = True
        self.mark = True
        self.block_end = True
        SAVE_REG.set(True)
        return self


class Mark(State):
    name = "Mark"
    """
    Mark -> Content
    Mark -> Block
    """

    def transit(self) -> State:
        self.content = CONTENT_STACK.pop_all()
        SPACE_EAT_REG.set(True)
        SAVE_REG.set(True)
        return BlockStart()


class TagStart(State):
    name = "TagStart"

    def transit(self) -> State:
        self.content = CONTENT_STACK.pop_all()
        TAG_STACK.append(self.content)
        SAVE_REG.set(True)
        return TagReadName()


class TagReadName(State):
    name = "Tag"

    def transit(self) -> State:
        res, reason = is_tag_name(CONTENT_STACK.content)
        if res:
            self.content = CONTENT_STACK.pop_all()
            SAVE_REG.set(True)
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
                SPACE_EAT_REG.set(True)
                SAVE_REG.set(True)
                return BlockStart()
        else:
            if reason in [OVER_MAX_LENGTH, NOT_MATCH]:
                return StopState()
            elif reason == POSSIBLE:
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
            SAVE_REG.set(True)
            return Content()
        else:
            if reason in [OVER_MAX_LENGTH, NOT_MATCH]:
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
        SAVE_REG.set(True)
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
                self.transit_list.append(self.current)
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
        # if NO_SAVE_REG.get():
        #     NO_SAVE_REG.set(False)
        #     return
        # if FORCE_SAVE_REG.get():
        #     self.transit_list.append(self.last)
        #     FORCE_SAVE_REG.set(False)
        if SAVE_REG.get():
            if self.transit_list[-1].name != self.last.name:
                self.transit_list.append(self.last)
            SAVE_REG.set(False)
        # if self.transit_list[-1].name != self.current.name:
        #     self.transit_list.append(self.current)
