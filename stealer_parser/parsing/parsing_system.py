"""Helper functions to parse system files.

The following grammar is implemented:

```
/* -------------------------------------------------------
   The Grammar
   ------------------------------------------------------- *

%start system
%%

system           : NEWLINE
                 | information
                 | header_line
                 ;
header_line      : WORD NEWLINE
                 | SPACE NEWLINE
                 | WORD header_line
                 ;
information      : uid_line
                 | computer_line
                 | hwid_line
                 | user_line
                 | ip_line
                 | country_line
                 ;
uid_line         : UID_PREFIX NEWLINE
                 | UID_PREFIX SPACE NEWLINE
                 | UID_PREFIX SPACE entry NEWLINE
                 | list_element uid_line
                 ;
computer_line    : COMPUTER_NAME_PREFIX NEWLINE
                 | COMPUTER_NAME_PREFIX SPACE NEWLINE
                 | COMPUTER_NAME_PREFIX SPACE entry NEWLINE
                 | list_element computer_line
                 ;
hwid_line        : HWID_PREFIX NEWLINE
                 | HWID_PREFIX SPACE NEWLINE
                 | HWID_PREFIX SPACE entry NEWLINE
                 | list_element hwid_line
                 ;
user_line        : USER_PREFIX NEWLINE
                 | USER_PREFIX SPACE NEWLINE
                 | USER_PREFIX SPACE entry NEWLINE
                 | list_element user_line
                 ;
ip_line          : IP_PREFIX NEWLINE
                 | IP_PREFIX SPACE NEWLINE
                 | IP_PREFIX SPACE entry NEWLINE
                 | list_element ip_line
                 ;
country_line     : COUNTRY_PREFIX NEWLINE
                 | COUNTRY_PREFIX SPACE NEWLINE
                 | COUNTRY_PREFIX SPACE entry NEWLINE
                 | list_element country_line
                 ;
log_date_line    : LOG_DATE_PREFIX NEWLINE
                 | LOG_DATE_PREFIX SPACE NEWLINE
                 | LOG_DATE_PREFIX SPACE entry NEWLINE
                 | list_element log_date_line
                 ;
list_element     : SPACE DASH SPACE
                 ;
entry            : WORD
                 | entry SPACE WORD
                 ;
```

Information about the compromised system are stored in text files that most of
the times named as follows:

- `system_info.txt`
- `System Info.txt`
- `information.txt`
- `Information.txt`
- `UserInformation.txt`
"""
from re import Match, Pattern, compile
from typing import Callable, TypeAlias

from verboselogs import VerboseLogger

from stealer_parser.models import System, SystemData
from stealer_parser.ply.src.ply.lex import LexToken

from .lexer_system import tokenize_system
from .parser import LogsParser, parse_entry

# Type alias for parsing function.
ParsingFunc: TypeAlias = Callable[[LogsParser, System], bool]

IP_REGEX: str = r"(?i)\b(ip(address)?)\b: ?(\S+)"
# Let's break down this regex:
#
# (?i)    Case insensitive
# \b(ip(address)?)\b:
#         Match substring.
#  ?      Optional space.
# (\S+)   Match one or more non-whitespace character.
#         Group 3: The IP address.
IP_PATTERN: Pattern[str] = compile(IP_REGEX)


def retrieve_ip_only(text: str, system_data: SystemData) -> None:
    """Retrieve IP address from a file.

    Parameters
    ----------
    text : str
        The file text content.
    system_data : stealurk.models.leak.SystemData
        The compromised system information.

    """
    matched: Match[str] | None = IP_PATTERN.search(text)

    if matched and matched.group(3):
        if not system_data.system:
            system_data.system = System()
        system_data.system.ip_address = matched.group(3)


def parse_uid_line(parser: LogsParser, system: System) -> bool:
    """Parse machine ID (UID).

    uid_line : UID_PREFIX NEWLINE
             | UID_PREFIX SPACE NEWLINE
             | UID_PREFIX SPACE entry NEWLINE
             | list_element uid_line

    """
    if parser.eat("UID_PREFIX"):
        if parser.eat("SPACE"):
            system.machine_id = parse_entry(parser)

        parser.eat("NEWLINE")
        return True

    return False


def parse_computer_line(parser: LogsParser, system: System) -> bool:
    """Parse computer name.

    computer_line : COMPUTER_NAME_PREFIX NEWLINE
                  | COMPUTER_NAME_PREFIX SPACE NEWLINE
                  | COMPUTER_NAME_PREFIX SPACE entry NEWLINE
                  | list_element computer_line

    """
    if parser.eat("COMPUTER_NAME_PREFIX"):
        if parser.eat("SPACE"):
            system.computer_name = parse_entry(parser)

        parser.eat("NEWLINE")
        return True

    return False


def parse_hwid_line(parser: LogsParser, system: System) -> bool:
    """Parse hardware ID.

    hwid_line : HWID_PREFIX NEWLINE
              | HWID_PREFIX SPACE NEWLINE
              | HWID_PREFIX SPACE entry NEWLINE
              | list_element hwid_line

    """
    if parser.eat("HWID_PREFIX"):
        if parser.eat("SPACE"):
            system.hardware_id = parse_entry(parser)

        parser.eat("NEWLINE")
        return True

    return False


def parse_username_line(parser: LogsParser, system: System) -> bool:
    """Parse computer's username.

    user_line : USERNAME_PREFIX NEWLINE
              | USERNAME_PREFIX SPACE NEWLINE
              | USERNAME_PREFIX SPACE entry NEWLINE
              | list_element user_line

    """
    if parser.eat("USERNAME_PREFIX"):
        if parser.eat("SPACE"):
            system.machine_user = parse_entry(parser)

        parser.eat("NEWLINE")
        return True

    return False


def parse_ip_line(parser: LogsParser, system: System) -> bool:
    """Parse IP address.

    ip_line : IP_PREFIX NEWLINE
            | IP_PREFIX SPACE NEWLINE
            | IP_PREFIX SPACE entry NEWLINE
            | list_element ip_line

    """
    ip_token: LexToken | None = parser.eat("IP_PREFIX")

    if ip_token:
        if parser.eat("SPACE"):
            if ip_token.value.lower() == "lanip" and system.ip_address:
                parser.position += 1  # Prefer IP over LANIP.
            else:
                system.ip_address = parse_entry(parser)

        parser.eat("NEWLINE")
        return True

    return False


def parse_country_line(parser: LogsParser, system: System) -> bool:
    """Parse machine's country.

    country_line : COUNTRY_PREFIX NEWLINE
                 | COUNTRY_PREFIX SPACE NEWLINE
                 | COUNTRY_PREFIX SPACE entry NEWLINE
                 | list_element country_line

    """
    if parser.eat("COUNTRY_PREFIX"):
        if parser.eat("SPACE"):
            system.country = parse_entry(parser)

        parser.eat("NEWLINE")
        return True

    return False


def parse_log_date_line(parser: LogsParser, system: System) -> bool:
    """Parse compromission date.

    log_date_line : LOG_DATE_PREFIX NEWLINE
                  | LOG_DATE_PREFIX SPACE NEWLINE
                  | LOG_DATE_PREFIX SPACE entry NEWLINE
                  | list_element log_date_line

    """
    if parser.eat("LOG_DATE_PREFIX"):
        if parser.eat("SPACE"):
            system.log_date = parse_entry(parser)

        parser.eat("NEWLINE")
        return True

    return False


def parse_system(
    logger: VerboseLogger, filename: str, text: str
) -> System | None:
    """Parse a logs system file.

    system : NEWLINE
           | information
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
    list of stealer_parser.models.system.System or None
        The parsed system information.

    Raises
    ------
    ply.lex.LexError
        If the lexer found an unexpected symbol.

    """
    tokens: list[LexToken] = tokenize_system(logger, filename, text)
    parser: LogsParser = LogsParser(tokens)
    system = System()

    # The parsing is way simpler than for passwords since each line appears
    # only once in the file.
    # On purpose, a lot of lines are skipped and no error is raised in case of
    # grammar error
    while parser.position < parser.size:
        token: LexToken = parser.get_current_token()

        match token.type:
            case "UID_PREFIX":
                parse_uid_line(parser, system)

            case "COMPUTER_NAME_PREFIX":
                parse_computer_line(parser, system)

            case "HWID_PREFIX":
                parse_hwid_line(parser, system)

            case "USERNAME_PREFIX":
                parse_username_line(parser, system)

            case "IP_PREFIX":
                parse_ip_line(parser, system)

            case "COUNTRY_PREFIX":
                parse_country_line(parser, system)

            case "LOG_DATE_PREFIX":
                parse_log_date_line(parser, system)

            case _:
                parser.position += 1  # skip

    # Append block data to output if it contains at least one attribute.
    return system if any(list(system.__dict__.values())) else None
