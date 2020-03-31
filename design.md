```text
. A MARKUP LANGUAGE
    - MARK: # ##
    - TAG \tittle\
    - BLOCK { }
    - CONTENT
. MARK
    - SINGLE LINE
        # xx
        > xx
        * xx
    - WRAP
        **xx**
        `xx`
        ```go
        package main
        ```
    - CONTEXT:
        [xx](xx)
        ![xx](xx)
    - SPECIAL
        | a | b |
        |---|---|
        | 1 | 2 |

. TAG
    - SINGLE LINE
        \TITTLE\ THIS IS THE TITTLE
    - PROPERTY
        \TITTLE [html=h1]\ THIS IS THE TITTLE

. BLOCK
    - WRAP
        \CODE [lang=Python]\ { import os }
    - NESTED
        \PARAGRAPH\ { this is an \HIGHLIGHT [color=red]\ { APPLE }}
    - CONTEXT
        \LINK [href="http://g4ba.xyz:1337"]\ { my blog }
        \IMAGE [file="file:///tmp/cat.png]\ { cute cat }
    - SPECIAL
        \TABLE [style=markdown]\ {
        | a | b |
        |---|---|
        | 1 | 2 |
        }

. CONTENT
    UNICODE
```

```grapivz
digraph Gatext{
  subgraph tag {
    node [style=filled];
    TagStart -> TagName -> TagEnd;
    label = "Tag";
  }
  subgraph attr {
    label = "Attr";
    AttrStart -> AttrName -> AttrEqual -> AttrValue -> AttrEnd;
  }
  
  subgraph block {
    label = "Block";
    BlockStart -> BlockContent -> BlockEnd;
  }
  
  start -> Content;
  Content -> Mark;
  Content -> Tag;

  Tag -> Block;
  Mark -> Block;

  Tag -> Content;
  Mark -> Content;
  Content -> end;

  start [shape=Mdiamond];
  end [shape=Msquare];
}

```