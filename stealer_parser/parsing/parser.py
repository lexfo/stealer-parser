"""Parser class to analyze stealer logs."""
import binascii
from base64 import b64decode
from typing import TypeAlias

from stealer_parser.models import Credential
from stealer_parser.ply.src.ply.lex import LexToken

from .lexer_passwords import PasswordToken
from .lexer_system import SystemToken

TokenType: TypeAlias = PasswordToken | SystemToken


class LogsParser:
    """Class defining a stealer logs parser.

    Instead of a tree, this parser generates a list of JSON-formatted objects.

    Attributes
    ----------
    _pos : int, default=0
        Index of the current token.
    _size : int, default=0
        Tokens count.
    _tokens : list of ply.lex.LexToken, default=[]
        The sequence of tokens produced by the lexer to iterate over.
    _output : list of stealer_parser.models.Credential, default=[]
        Parsed logs data stored in a list of JSON-formatted objects.

    Methods
    -------
    get_current_token()
        Get currently analyzed token.
    eat(expected_type, expected_value=None)
        Consume token if it matches expected type and, if provided, value.

    """

    def __init__(self, tokens: list[LexToken]) -> None:
        """Instantiate parser."""
        self._pos: int = 0
        self._size: int = len(tokens)
        self._tokens: list[LexToken] = tokens
        self._output: list[Credential] = []

    # Properties ##############################################################

    @property
    def position(self) -> int:
        """Get index of the current token."""
        return self._pos

    @position.setter
    def position(self, position: int) -> None:
        """Set index of the current token."""
        if position < 0 or position > self._size:
            raise IndexError(
                "Current token's position is out of range. Provide a number "
                f"between 0 and size ({self._size})."
            )

        self._pos = position

    @property
    def size(self) -> int:
        """Get tokens count."""
        return self._size

    @property
    def output(self) -> list[Credential]:
        """Get parser's output."""
        return self._output

    # Methods #################################################################

    def get_current_token(self) -> LexToken:
        """Get currently analyzed token.

        Raises
        ------
        IndexError
            If parser.position is out of range.

        Returns
        -------
        ply.lex.LexToken

        """
        return self._tokens[self._pos]

    def eat(
        self, expected_type: TokenType, expected_value: str | None = None
    ) -> LexToken | None:
        """Consume token if it matches expected type and, if provided, value.

        Parameters
        ----------
        expected_type : stealurk.parsing.parser.TokenType
            The expected token type.
        expected_value : str, optional
            The expected token value.

        Returns
        -------
        ply.lex.LexToken or None
            The consumed token. Otherwise, None.

        """
        eaten_token: LexToken | None = None

        if self._pos < self._size:
            token: LexToken = self.get_current_token()

            if token.type == expected_type:
                if expected_value is None or token.value == expected_value:
                    eaten_token = token
                    self._pos += 1

        return eaten_token


def parse_entry(parser: LogsParser) -> str | None:
    """Concatenate words and spaces until newline.

    entry : WORD
          | entry SPACE WORD
    """
    entry: str = ""

    while parser.position < parser.size:
        token: LexToken | None = parser.get_current_token()
        parser.position += 1

        if not token or token.type not in ("WORD", "SPACE"):
            break

        entry += token.value

    # NOTE: A valid entry can be empty or only spaces.
    return entry if entry else None


def parse_multiline_entry(parser: LogsParser) -> str | None:
    """Concatenate words and newlines. The entry is often base64 encoded.

    multiline_entry : WORD
                    | multiline_entry NEWLINE WORD

    """
    entry: str = ""

    while parser.position < parser.size:
        token: LexToken | None = parser.eat("WORD") or parser.eat("NEWLINE")

        if not token:
            break

        if token.type == "WORD":
            entry += token.value

    if entry:
        try:
            return b64decode(entry).decode("utf-8").replace("\n", "")

        except (binascii.Error, ValueError):
            pass

        return entry

    # NOTE: A valid entry can be empty or only spaces.
    return None


def skip_header_line(parser: LogsParser) -> bool:
    """Skip ASCII art headers and other irrelevant data such as separators.

    header_line : WORD NEWLINE
                | SPACE NEWLINE
                | WORD header_line

    """
    is_header: bool = bool(parser.eat("WORD") or parser.eat("SPACE"))

    if not is_header:
        return False

    while is_header:
        is_header = bool(parser.eat("WORD") or parser.eat("SPACE"))

    return bool(parser.eat("NEWLINE"))


def skip_seller_block(parser: LogsParser) -> bool:
    """Skip seller information.

    seller_block    : SELLER_PREFIX SPACE entry
                    | host_line
                    | seller_block NEWLINE

    """
    is_seller_block: bool = bool(parser.eat("SELLER_PREFIX"))

    if not is_seller_block:
        return False

    while is_seller_block:
        if parser.eat("SPACE"):
            parse_entry(parser)
        parser.eat("NEWLINE")

        is_seller_block = bool(
            parser.eat("SELLER_PREFIX") or parser.eat("HOST_PREFIX")
        )

    return True
