"""Bounded quoted KeyValues parsing with a byte-preserving target mapping edit."""

import re
from dataclasses import dataclass

from preparation_common import MAX_DEPTH, MAX_JSON, MAX_STRING, app_id, require, string

TOKEN = re.compile(r'\s+|//[^\n]*|"(?:[^"\\]|\\.)*"|[{}]')
TOOL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)


@dataclass
class Entry:
    value: object
    start: int
    end: int
    value_start: int
    close: int = 0


class Document:
    def __init__(self, raw):
        require(len(raw) <= MAX_JSON, "VDF too large")
        self.text = raw.decode("utf-8")
        self.tokens = []
        end = 0
        for match in TOKEN.finditer(self.text):
            require(match.start() == end, "unsupported VDF token")
            end = match.end()
            token = match.group()
            if not token.isspace() and not token.startswith("//"):
                self.tokens.append((token, match.start(), match.end()))
        require(end == len(self.text), "invalid VDF tail")
        self.position = 0
        self.root = self._block(0)

    @staticmethod
    def _quoted(token):
        require(token.startswith('"'), "expected VDF string")
        value = re.sub(r'\\(["\\])', r'\1', token[1:-1])
        require(len(value.encode("utf-8")) <= MAX_STRING, "VDF string too long")
        return value

    def _block(self, depth, opening=None):
        require(depth <= MAX_DEPTH, "VDF nesting too deep")
        result = {}
        while self.position < len(self.tokens):
            token, start, _ = self.tokens[self.position]
            self.position += 1
            if token == "}":
                require(opening is not None, "unexpected VDF close")
                return Entry(result, opening[1], self.tokens[self.position - 1][2], opening[1], start)
            key = self._quoted(token)
            require(key not in result and self.position < len(self.tokens), "duplicate or incomplete VDF entry")
            following = self.tokens[self.position]
            self.position += 1
            if following[0] == "{":
                node = self._block(depth + 1, following)
                node.start = start
            else:
                node = Entry(self._quoted(following[0]), start, following[2], following[1])
            result[key] = node
        require(opening is None, "unclosed VDF block")
        return Entry(result, 0, len(self.text), 0, len(self.text))

    def node(self, path):
        node = self.root
        for key in path:
            require(type(node.value) is dict and key in node.value, "missing VDF block")
            node = node.value[key]
        return node

    def value(self):
        def unpack(node):
            return {key: unpack(item) for key, item in node.value.items()} if type(node.value) is dict else node.value
        return unpack(self.root)


def parse_vdf(raw):
    return Document(raw).value()


def patch_game_mapping(raw, registration_id, tool):
    """Modify only this game's name or insert its block. All other bytes survive."""
    key = app_id(registration_id)
    require(key == registration_id, "canonical unsigned game ID required")
    require(type(tool) is str and TOOL_ID.fullmatch(tool), "invalid tool ID")
    document = Document(raw)
    steam = document.node(("InstallConfigStore", "Software", "Valve", "Steam"))
    require(type(steam.value) is dict, "Steam VDF block required")
    mapping = steam.value.get("CompatToolMapping")
    fragment = f'\n\t"{key}" {{ "name" "{tool}" "config" "" "priority" "250" }}\n'
    if mapping is None:
        position = steam.close
        replacement = '\n"CompatToolMapping" {' + fragment + '}\n'
        text = document.text[:position] + replacement + document.text[position:]
    else:
        require(type(mapping.value) is dict, "mapping block required")
        game = mapping.value.get(key)
        if game is None:
            text = document.text[:mapping.close] + fragment + document.text[mapping.close:]
        else:
            require(type(game.value) is dict, "game mapping must be a block")
            name = game.value.get("name")
            if name is None:
                text = document.text[:game.close] + f'\n"name" "{tool}"\n' + document.text[game.close:]
            else:
                require(type(name.value) is str, "mapping name must be a string")
                text = document.text[:name.value_start] + '"' + string(tool) + '"' + document.text[name.end:]
    result = text.encode("utf-8")
    require(len(result) <= MAX_JSON, "result VDF too large")
    # Parse the candidate before it can reach a writer.
    parse_vdf(result)
    return result
