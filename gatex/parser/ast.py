from pandocfilters import *

version = {"pandoc-api-version": [1, 20]}
meta = {"meta": {}}


def inline_funcs_builder(func_name: str, content: str) -> dict:
    if func_name in ["Str", "Emph", "Strong"]:
        return eval(func_name)(content)
    elif func_name in ["Code"]:
        return eval(func_name)(["", [], []], content)
    else:
        raise Exception("{} is not available func name")


def block_funcs_builder(func_name: str, content: str) -> dict:
    if func_name in ["Plain", "Para", "BulletList"]:
        return eval(func_name)(content)
    elif func_name in ["CodeBlock"]:
        return eval(func_name)(["", [], []], content)
    else:
        raise Exception("{} is not available func name")


class Tag(object):
    # inline element
    def __init__(self, name: str, content: str):
        self.name = name
        self.content = content

    def build(self, render_mapping: dict) -> dict:
        func_name = render_mapping.get(self.name, "Plain")
        return inline_funcs_builder(func_name, self.content)


class Mark(Tag):
    pass


class TagBlock(object):
    # Block element
    def __init__(self, name: str, content: str):
        self.name = name
        self.content = content

    def build(self, render_mapping: dict) -> dict:
        func_name = render_mapping.get(self.name, "Plain")
        return block_funcs_builder(func_name, self.content)


class Blocks(list):
    def dumps(self):
        return json.dumps(self)


if __name__ == "__main__":
    # pandoc -s test.md -t json | jq | pandoc -s -f json
    print(Plain([Str("ads")]))
