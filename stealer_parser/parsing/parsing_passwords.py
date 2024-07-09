"""Helper functions to parse password files.

The following grammar is implemented:

```
/* -------------------------------------------------------
   The Grammar
   ------------------------------------------------------- *

%start passwords
%%

passwords        : NEWLINE
                 | user_block
                 | seller_block
                 | header_line
                 ;
header_line      : WORD NEWLINE
                 | SPACE NEWLINE
                 | WORD header_line
                 ;
seller_block     : SELLER_PREFIX SPACE entry
                 | host_line
                 | seller_block NEWLINE
                 ;
user_block       : soft_line host_line user_line password_line
                 | host_line user_line password_line
                 | soft_line user_line password_line
                 ;
soft_line        : SOFT_PREFIX NEWLINE
                 | SOFT_PREFIX SPACE NEWLINE
                 | SOFT_PREFIX SPACE entry NEWLINE
                 | soft_line profile_line NEWLINE
                 | SOFT_NO_PREFIX NEWLINE
                 ;
profile_line     : 'profile:' SPACE WORD
                 ;
host_line        : HOST_PREFIX NEWLINE
                 | HOST_PREFIX SPACE NEWLINE
                 | HOST_PREFIX SPACE entry NEWLINE
                 ;
user_line        : USER_PREFIX NEWLINE
                 | USER_PREFIX SPACE NEWLINE
                 | USER_PREFIX SPACE entry NEWLINE
                 ;
password_line    : PASSWORD_PREFIX NEWLINE
                 | PASSWORD_PREFIX SPACE NEWLINE
                 | PASSWORD_PREFIX SPACE entry NEWLINE
                 | multiline_entry NEWLINE
                 ;
multiline_entry  : WORD
                 | multiline_entry NEWLINE WORD
                 ;
entry            : WORD
                 | entry SPACE WORD
                 ;
```

The credentials are stored in text files that most of the times named as
follows:

- `password.txt` ;
- `Password.txt` ;
- `All passwords.txt` ;
- `AllPasswords_list.txt` ;
- `_AllPasswords_list.txt`.
"""
from json import dumps
from pathlib import Path
from re import Match, Pattern, compile, search
from typing import Callable, TypeAlias

from verboselogs import VerboseLogger

from stealer_parser.helpers import dump_to_file
from stealer_parser.models import (
    Credential,
    extract_credential_domain_name,
    normalize_credential_text,
    split_credential_email,
)
from stealer_parser.ply.src.ply.lex import LexToken

from .lexer_passwords import tokenize_passwords
from .parser import (
    LogsParser,
    parse_entry,
    parse_multiline_entry,
    skip_header_line,
    skip_seller_block,
)

# Type alias for parsing function.
ParsingFunc: TypeAlias = Callable[[LogsParser, Credential], bool]

PASSWORDS_BROWSER_REGEX: str = r"(?i)\bPasswords\[([A-Za-z0-9_ ]+)\]\S+\.txt\b"
# Let's break down this regex:
#
# (?i)       Case insensitive.
# \b         Word boundary.
# Passwords  Match substring.
# \[([A-Za-z0-9_ ]+)\]
#            A sequence of characters between brackets.
#              Group 1: The browser name
# \S+\.txt   Characters followed by .txt
# \b         Word boundary.

SPECIAL_SOFT_PATTERN: Pattern[str] = compile(r'\["(\S+)" = "(\S+)"\]')
FILEGRABBER_PATTERN: Pattern[str] = compile(
    r"(?i)(filegrabber|grabfiles|desktop|documents|usb)\b"
)


def get_browser_name(filename: str) -> str | None:
    """Retrieve a browser name from passwords file's name.

    Parameters
    ----------
    filename : str
        The file to parse.

    Returns
    -------
    str
        The browser filename if found. Otherwise, None.

    """
    matched: Match[str] | None = search(PASSWORDS_BROWSER_REGEX, filename)

    return matched.group(1) if matched else None


def skip_profile_line(parser: LogsParser) -> None:
    """Skip web browser's profile line.

    profile_line : 'profile:' SPACE WORD

    """
    if parser.eat("WORD", "profile:"):
        while parser.eat("WORD") or parser.eat("SPACE"):
            pass


def parse_software_line(parser: LogsParser, credential: Credential) -> bool:
    """Parse software data (web browser, email client).

    soft_line   : SOFT_PREFIX NEWLINE
                | SOFT_PREFIX SPACE NEWLINE
                | SOFT_PREFIX SPACE entry NEWLINE
                | soft_line profile_line NEWLINE
                | SOFT_NO_PREFIX NEWLINE

    """
    if parser.eat("SOFT_PREFIX"):
        if parser.eat("SPACE"):
            credential.software = parse_entry(parser)

        parser.eat("NEWLINE")
        skip_profile_line(parser)
        return True

    software: LexToken | None = parser.eat("SOFT_NO_PREFIX")

    if software:
        matched: Match[str] | None = SPECIAL_SOFT_PATTERN.match(software.value)

        if matched:
            credential.software = f"{matched.group(1)} {matched.group(2)}"
            parser.eat("NEWLINE")
            return True

        parser.position -= 1

    return False


def parse_host_line(parser: LogsParser, credential: Credential) -> bool:
    """Parse host data (website visited when user's data was stolen).

    host_line   : HOST_PREFIX NEWLINE
                | HOST_PREFIX SPACE NEWLINE
                | HOST_PREFIX SPACE entry NEWLINE

    """
    if parser.eat("HOST_PREFIX"):
        if parser.eat("SPACE"):
            credential.host = parse_entry(parser)
            extract_credential_domain_name(credential)

        parser.eat("NEWLINE")
        return True

    return False


def parse_user_line(parser: LogsParser, credential: Credential) -> bool:
    """Parse username or email address.

    user_line   : USER_PREFIX NEWLINE
                | USER_PREFIX SPACE NEWLINE
                | USER_PREFIX SPACE entry NEWLINE

    """
    if parser.eat("USER_PREFIX"):
        if parser.eat("SPACE"):
            credential.username = parse_entry(parser)
            split_credential_email(credential)

        parser.eat("NEWLINE")
        return True

    return False


def parse_password_line(parser: LogsParser, credential: Credential) -> bool:
    """Parse user's password.

    password_line   : PASSWORD_PREFIX NEWLINE
                    | PASSWORD_PREFIX SPACE NEWLINE
                    | PASSWORD_PREFIX SPACE entry NEWLINE
                    | multiline_entry NEWLINE

    """
    if parser.eat("PASSWORD_PREFIX"):
        if parser.eat("SPACE"):
            current: int = parser.position
            password: str | None = parse_entry(parser)

            if (
                not parser.eat("NEWLINE")
                and parser.eat("WORD")
                and (
                    credential.host
                    and credential.host.startswith("android://")
                )
            ):
                # NOTE: Special case: android passwords are multi-line.
                parser.position = current
                password = parse_multiline_entry(parser)

            credential.password = password

        return True

    return False


def parse_line(
    parsing_funcs: list[ParsingFunc],
    parser: LogsParser,
    credential: Credential,
) -> bool:
    """Call the list functions in turn until one of them evaluates to True.

    Sometimes, the logs data order can vary. This helper aims to handle any
    possible configuration.

    For example:
        soft_line host_line user_line pass_line
    and:
        host_line user_line password_line soft_line
    must be both handled.

    Parameters
    ----------
    parsing_funcs : list of ParsingFunc
        The functions to test.
    parser : stealurk.parsing.parser.LogsParser
        The parser object.
    credential : stealurk.models.credential.Credential
        The parsed output.

    Returns
    -------
    bool

    """
    for func in parsing_funcs:
        if func(parser, credential):  # Line was successfully parsed.
            parsing_funcs.remove(func)
            while parser.eat("NEWLINE") or parser.eat("SPACE"):
                pass
            return True

    return False


def parse_user_block(parser: LogsParser, filename: str) -> bool:
    """Parse user data (software, host/URL, username and password).

    user_block  : soft_line host_line user_line password_line
                | host_line user_line password_line
                | soft_line user_line password_line

    """
    credential = Credential()
    parsing_funcs: list[ParsingFunc] = [
        parse_software_line,
        parse_host_line,
        parse_user_line,
        parse_password_line,
    ]

    # This is a work around to handle any possible lines order of appearance.
    while True:
        if not parse_line(parsing_funcs, parser, credential):
            break

    # Append block data to output if it contains at least one attribute.
    # Indeed, case can happen where a user block was empty but grammaticaly
    # correct.
    # For example: "Soft: \nHost: \nUser: \nPassword:\n"
    if any(list(credential.__dict__.values())):
        # If the software/browser was not found in file text, search filename.
        if parse_software_line in parsing_funcs:
            credential.software = get_browser_name(filename)
            if credential.software:
                parsing_funcs.remove(parse_software_line)

        credential.filepath = filename
        normalize_credential_text(credential)
        parser.output.append(credential)
        return True

    # Must have parsed at least 3 lines.
    return len(parsing_funcs) < 2


def parse_passwords(
    logger: VerboseLogger, filename: str, text: str
) -> list[Credential]:
    """Parse a logs passwords file.

    passwords : linebreak
              | user_block
              | header_line

    Parameters
    ----------
    logger : verboselogs.VerboseLogger
        The program's logger.
    filename : str
        The file to parse.
    text : str
        The file text content.

    Returns
    -------
    list of stealer_parser.models.credential.Credential
        The parsed user credentials.

    Raises
    ------
    SyntaxError
        If not every token was consumed.
    ply.lex.LexError
        If the lexer found an unexpected symbol.

    """
    tokens: list[LexToken] = tokenize_passwords(logger, filename, text)
    parser = LogsParser(tokens)
    parsed_seller: bool = False

    while parser.position < parser.size:
        if not parsed_seller:
            parsed_seller = skip_seller_block(parser)
            if parsed_seller:
                pass

        if (
            parser.eat("NEWLINE")
            or skip_header_line(parser)
            or parse_user_block(parser, filename)
        ):
            pass
        else:
            break

    if parser.position != parser.size:
        err_msg: str = (
            f"Unexpected token '{parser.get_current_token()}' at position "
            f"{parser.position}/{parser.size}."
        )
        doc: str = dumps(tokens, ensure_ascii=False, default=vars, indent=4)
        filepath = Path(filename)
        logs_dir: str = f"logs/parsing/{filepath.parent}"
        dump_to_file(
            logger,
            f'{logs_dir}/{filepath.with_suffix(".log").name}',
            f"{err_msg}\n{doc}",
        )
        dump_to_file(logger, f"{logs_dir}/{filepath.name}", text)
        raise SyntaxError(err_msg)

    return parser.output
