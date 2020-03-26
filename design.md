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
        \LINK [url="http://g4ba.xyz:1337"]\ { my blog }
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