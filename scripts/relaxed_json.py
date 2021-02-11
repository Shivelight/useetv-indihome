"""
relaxedjson (https://github.com/simon-engledew/relaxedjson) is a library
for parsing JSON that is missing quotes around its keys.
Uses the parser-combinator library Parsec (https://github.com/sighingnow/parsec.py)
To install from pypi::
    pip install relaxedjson
To install as an egg-link in development mode::
    python setup.py develop -N
"""

import re
from parsec import (
    sepBy,
    regex,
    string,
    generate,
    many,
    endBy
)

whitespace = regex(r'\s*', re.MULTILINE)

lexeme = lambda p: p << whitespace

comment = string('/*') >> regex(r'(?:[^*]|\*(?!\/))+', re.MULTILINE) << string('*/')
comment = lexeme(comment)

lbrace = lexeme(string('{'))
rbrace = lexeme(string('}'))
lbrack = lexeme(string('['))
rbrack = lexeme(string(']'))
colon = lexeme(string(':'))
comma = lexeme(string(','))
true = lexeme(string('true')).result(True)
false = lexeme(string('false')).result(False)
null = lexeme(string('null')).result(None)
quote = string('"') | string("'")

def number():
    return lexeme(
        regex(r'-?(0|[1-9][0-9]*)([.][0-9]+)?([eE][+-]?[0-9]+)?')
    ).parsecmap(float)

def to_unichr(value):
    return unichr(int(value[1:], 16))

def charseq(end_quote):
    def string_part():
        return regex(r'[^{}\\]+'.format(end_quote))

    def string_esc():
        return string('\\') >> (
            string('\\')
            | string('/')
            | string('b').result('\b')
            | string('f').result('\f')
            | string('n').result('\n')
            | string('r').result('\r')
            | string('t').result('\t')
            | regex(r'u[0-9a-fA-F]{4}').parsecmap(to_unichr)
            | string(end_quote)
        )
    return string_part() | string_esc()

class StopGenerator(StopIteration):
    def __init__(self, value):
        self.value = value

@lexeme
@generate
def quoted():
    end_quote = yield quote
    body = yield many(charseq(end_quote))
    yield string(end_quote)
    raise StopGenerator(''.join(body))

@generate
def array():
    yield lbrack << many(comment)
    elements = yield sepBy(value, comma)
    yield rbrack << many(comment)
    raise StopGenerator(elements)


@generate
def object_pair():
    key = yield quoted | lexeme(regex(r'[a-zA-Z][-_a-zA-Z0-9]*'))
    yield many(comment) << colon << many(comment)
    val = yield value
    raise StopGenerator((key, val))


@generate
def json_object():
    yield lbrace << many(comment)
    pairs = yield sepBy(object_pair, comma)
    yield many(comment) << rbrace
    raise StopGenerator(dict(pairs))

value = quoted | number() | json_object | array | true | false | null

parser = whitespace >> (json_object | array)

def parse(text):
    """
    Attempt to parse JSON text, returning an object
    :param text: String containing json
    :rtype: dict or list
    :raises: parsec.ParseError
    """
    return parser.parse_strict(text)

__all__ = ['parse']
