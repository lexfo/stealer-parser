"""Token list and grammar rules definition.

```
/* -------------------------------------------------------
   The grammar symbols
   ------------------------------------------------------- */

%token  WORD
%token  NEWLINE
%token  SPACE

%token  SOFT_PREFIX
/*      'Soft:' | 'SOFT:' | 'Browser:' | 'Application:' | 'Storage:' */

%token  SOFT_NO_PREFIX
/*      '["Browser" = "Profile"]' */

%token  HOST_PREFIX
/*      'Host:' | 'Hostname:' | 'URL:' | 'UR1:' */

%token  USER_PREFIX
/*      'USER LOGIN:' | 'Login:' | 'Username:' | 'USER:' | 'U53RN4M3:' */

%token  PASSWORD_PREFIX
/*      'USER PASSWORD:' | 'Password:' | 'PASS:' | 'P455W0RD:' */

%token  SELLER_PREFIX
/*      'Seller:' | 'Log Tools:' | 'Free Logs:' */
```
"""
import re
from pathlib import Path
from typing import Literal, TypeAlias, get_args

from verboselogs import VerboseLogger

from stealer_parser.helpers import dump_to_file
from stealer_parser.ply.src.ply.lex import Lexer, LexError, LexToken, lex

# The ignored characters.
t_ignore: str = "\t\r"

# Ply Lexer's rules are added in the following order:
# 1. All tokens defined by functions are added in the same order as they appear
#    in the lexer file.
# 2. Tokens defined by strings are added next by sorting them in order of
#    decreasing regular expression length (longer expressions are added first).
#
# That's why some tokens are defined as functions below.

# The token types below are sorted in the expected definition order.
PasswordToken: TypeAlias = Literal[
    "SOFT_PREFIX",
    "SOFT_NO_PREFIX",
    "HOST_PREFIX",
    "USER_PREFIX",
    "PASSWORD_PREFIX",
    "SELLER_PREFIX",
    "WORD",
    "NEWLINE",
    "SPACE",
]

# The grammar symbols.
tokens: tuple[str, ...] = get_args(PasswordToken)


# The token definitions.
# They must be defined according the order of TokenType.


# 'Soft:' | 'SOFT:' | 'Browser:' | 'Application:' | 'Storage'
def t_SOFT_PREFIX(token: LexToken) -> LexToken:
    r"\b(soft|browser|application|storage)\b:"
    return token


# '["Browser" = "Profile"]'
def t_SOFT_NO_PREFIX(token: LexToken) -> LexToken:
    r'\["(\S+)"\ =\ "(\S+)"\]'
    return token


# 'Host:' | 'Hostname:' | 'URL:' | 'UR1:'
def t_HOST_PREFIX(token: LexToken) -> LexToken:
    r"\b(host(name)?|url|ur1)\b:"
    return token


# 'USER LOGIN:' | 'Login:' | 'Username:' | 'USER:' | 'U53RN4M3:'
def t_USER_PREFIX(token: LexToken) -> LexToken:
    r"\b(user\ login|user(name)?|login|u53rn4m3)\b:"
    return token


# 'USER PASSWORD:' | 'Password:' | 'PASS:' | 'P455W0RD:'
def t_PASSWORD_PREFIX(token: LexToken) -> LexToken:
    r"\b(user\ password|pass(word)?|p455w0rd)\b:"  # nosec
    return token


# 'Seller:' | 'Log Tools:' | 'Free Logs:'
def t_SELLER_PREFIX(token: LexToken) -> LexToken:
    r"\b(seller|log\ tools|free\ logs)\b:"  # nosec
    return token


def t_WORD(token: LexToken) -> LexToken:
    r"\S+"
    return token


t_NEWLINE = r"\n+"
t_SPACE = r"\ +"


# Handle lexing errors.
def t_error(token: LexToken) -> None:
    """Log lexing error to file."""
    next_newline: int = token.value.find("\n") - 1
    token_line: str = (
        token.value[0:next_newline] if next_newline > 0 else token.value[0:]
    )

    print(
        f"Illegal character '{token.value[0]}' at index {token.lexpos}: "
        f"'{token_line}'"
    )


def tokenize_passwords(
    logger: VerboseLogger, filename: str, text: str
) -> list[LexToken]:
    """Tokenize a passwords file.

    Parameters
    ----------
    logger : verboselogs.VerboseLogger
        The program's logger.
    filename : str
        The file to tokenize.
    text : str
        The file text content.

    Returns
    -------
    list of ply.lex.LexToken
        The produced tokens.

    Raises
    ------
    ply.lex.LexError
        If an illegal character was found.
    SyntaxError
        If can't build lexer.

    """
    # The tokens definitions and the lexer instantiation must be in the same
    # file.
    lexer: Lexer = lex(reflags=re.ASCII | re.IGNORECASE | re.VERBOSE)

    try:
        lexer.input(text)

        return list(lexer)

    except (LexError, SyntaxError) as err:
        filepath = Path(filename)
        logs_dir: str = f"logs/lexing/{filepath.parent}"

        dump_to_file(
            logger, f'{logs_dir}/{filepath.with_suffix(".log").name}', str(err)
        )
        dump_to_file(logger, f"{logs_dir}/{filepath.name}", text)
        raise
