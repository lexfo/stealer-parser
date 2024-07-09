"""Token list and grammar rules definition.

```
/* -------------------------------------------------------
   The grammar symbols
   ------------------------------------------------------- */

%token  WORD
%token  NEWLINE
%token  SPACE
%token  DASH

%token  UID_PREFIX
/*      'UID:' | 'MachineID:' */

%token  COMPUTER_NAME_PREFIX
/*      'Computer:' | 'ComputerName:' | 'Computer Name:' | 'PC Name:' |
        'Hostname:' | 'MachineName:' */

%token  HWID_PREFIX
/*      'HWID:' */

%token  USERNAME_PREFIX
/*      'User Name:' | 'UserName:' | 'User:' */

%token  IP_PREFIX
/*      'IP:' | 'Ip:' | 'IPAddress:' | 'IP Address:' | 'LANIP:' */

%token  COUNTRY_PREFIX
/*      'Country:' | 'Country Code:' */

%token  LOG_DATE_PREFIX
/*      'Log date:' | 'Last seen:' | 'Install Date:' */

%token  OTHER_PREFIX
/*      'User Agents:' | Installed Apps:' | 'Current User:' | 'Process List:' */
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
SystemToken: TypeAlias = Literal[
    "OTHER_PREFIX",
    "UID_PREFIX",
    "COMPUTER_NAME_PREFIX",
    "HWID_PREFIX",
    "USERNAME_PREFIX",
    "IP_PREFIX",
    "COUNTRY_PREFIX",
    "LOG_DATE_PREFIX",
    "WORD",
    "NEWLINE",
    "SPACE",
]

# The grammar symbols.
tokens: tuple[str, ...] = get_args(SystemToken)


# The token definitions.
# They must be defined according the order of TokenType.


# 'User Agents:' | Installed Apps:' | 'Current User:' | 'Process List:'
def t_OTHER_PREFIX(token: LexToken) -> LexToken:
    r"\b(user\ agents|installed\ apps|current\ user|process\ list)\b:"
    return token


# 'UID:' | 'MachineID:'
def t_UID_PREFIX(token: LexToken) -> LexToken:
    r"\b(uid|machineid)\b:"
    return token


# 'Computer' | 'ComputerName:' | 'Computer Name:' | 'PC Name:' | 'Hostname:'
# | 'MachineName:'
def t_COMPUTER_NAME_PREFIX(token: LexToken) -> LexToken:
    r"\b((computer(\ ?name)?)|pc\ name|hostname|machinename)\b:"
    return token


# 'HWID:'
def t_HWID_PREFIX(token: LexToken) -> LexToken:
    r"\b(hwid)\b:"
    return token


# 'User Name:' | 'UserName:' | 'User:'
def t_USERNAME_PREFIX(token: LexToken) -> LexToken:
    r"\b(user(\ ?name)?)\b:"
    return token


# 'IP:' | 'Ip:' | 'IPAddress:' | 'IP Address:' | 'LANIP:'
def t_IP_PREFIX(token: LexToken) -> LexToken:
    r"\b((ip(\ ?address)?)|lanip)\b:"
    return token


# 'Country:' | 'Country Code:'
def t_COUNTRY_PREFIX(token: LexToken) -> LexToken:
    r"\b(country(\ code)?)\b:"
    return token


# 'Log date:' | 'Last seen:' | 'Install Date:'
def t_LOG_DATE_PREFIX(token: LexToken) -> LexToken:
    r"\b(log\ date|last\ seen|install\ date)\b:"
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


def tokenize_system(
    logger: VerboseLogger, filename: str, text: str
) -> list[LexToken]:
    """Tokenize a system file.

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

    except LexError as err:
        filepath = Path(filename)
        logs_dir: str = f"logs/lexing/{filepath.parent}"

        dump_to_file(
            logger, f'{logs_dir}/{filepath.with_suffix(".log").name}', str(err)
        )
        dump_to_file(logger, f"{logs_dir}/{filepath.name}", text)
        raise
