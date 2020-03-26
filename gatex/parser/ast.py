class Node(object):
    name: str = ""
    content: str = ""
    children = []

    def __repr__(self):
        res = []
        for n in self.children:
            res.append(str(n))
        return {"{}: {}".format(self.name, self.content): res}


class TagStart(Node):
    name: str = "TAG-START"


class TagStop(Node):
    name: str = "TAG-STOP"


class TagName(Node):
    name: str = "TAG-NAME"


class Tag(Node):
    name: str = "TAG"


class NestedStart(Node):
    name: str = "NestedStart"


class NestedStop(Node):
    name: str = "NestedStop"


class Content(Node):
    name: str = "Content"
