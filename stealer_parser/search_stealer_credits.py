"""Search for archive's stealer credits.

Some files contain credits to the stealer that harvested the data. It usually
is an ASCII art banner or a link to a Telegram channel.
"""
import re

from stealer_parser.models import StealerNameType

# ASCII art stealers signatures
DCRAT_HEADER: str = (
    "  ___           _      ___             _        _   ___    _ _____ \n"
    " |   \\ __ _ _ _| |__  / __|_ _ _  _ __| |_ __ _| | | _ \\  /_\\_   _|\n"
    " | |) / _` | '_| / / | (__| '_| || (_-<  _/ _` | | |   / / _ \\| |  \n"
    " |___/\\__,_|_| |_\\_\\  \\___|_|  \\_, /__/\\__\\__,_|_| |_|_\\/_/ "
    "\\_\\_|  \n"
    "                               |__/                                \n"
)

META_HEADER: str = (
    "*              / \\ / \\ / \\ / \\                *\n"
    "*             ( M | E | T | A )               *\n"
    "*              \\_/ \\_/ \\_/ \\_/                *\n"
)

RACCOON_HEADER: str = (
    "░░░░░░░░░░░░░░░▄▄▄▄▄▄▄▄░░░░░░░░░░░░░░\n"
    "░▄█▀███▄▄████████████████████▄▄███▀█░\n"
    "░█░░▀████████████████████████████░░█░\n"
    "░░█▄░░▀███████████████████████░░░░▄▀░\n"
    "░░░▀█▄▄████▀▀▀░░░░██░░░▀▀▀████▄▄▄█▀░░\n"
    "░░░▄███▀▀░░░░░░░░░██░░░░░░░░░▀███▄░░░\n"
    "░░▄██▀░░░░░▄▄▄██▄▄██░▄██▄▄▄░░░░░▀██▄░\n"
    "▄██▀░░░▄▄▄███▄██████████▄███▄▄▄░░░▀█▄\n"
    "▀██▄▄██████████▀░███▀▀▀█████████▄▄▄█▀\n"
    "░░▀██████████▀░░░███░░░▀███████████▀░\n"
    "░░░░▀▀▀██████░░░█████▄░░▀██████▀▀░░░░\n"
    "░░░░░░░░░▀▀▀▀▄░░█████▀░▄█▀▀▀░░░░░░░░░\n"
    "░░░░░░░░░░░░░░▀▀▄▄▄▄▄▀▀░░░░░░░░░░░░░░\n"
)

REDLINE_HEADER: str = (
    "*   ____  _____ ____  _     ___ _   _ _____   *\n"
    "*  |  _ \\| ____|  _ \\| |   |_ _| \\ | | ____|  *\n"
    "*  | |_) |  _| | | | | |    | ||  \\| |  _|    *\n"
    "*  |  _ <| |___| |_| | |___ | || |\\  | |___   *\n"
    "*  |_| \\_|_____|____/|_____|___|_| \\_|_____|  *\n"
)
# Headers with no slash character (they are sometimes removed by aggregators).
REDLINE_HEADER_MALFORMED: str = (
    "*   ____  _____ ____  _     ___ _   _ _____   *\n"
    "*  |  _ | ____|  _ | |   |_ _|  | | ____|     *\n"
    "*  | |_) |  _| | | | | |    | ||  | |  _|     *\n"
    "*  |  _ <| |___| |_| | |___ | || |  | |___    *\n"
    "*  |_| _|_____|____/|_____|___|_| _|_____|    *\n"
)

STEALC_HEADER: str = (
    " ______     ______   ______     ______     __         ______\n"
    "/\\  ___\\   /\\__  _\\ /\\  ___\\   /\\  __ \\   /\\ \\       /\\  "
    "___\\\n"
    "\\ \\___  \\  \\/_/\\ \\/ \\ \\  __\\   \\ \\  __ \\  \\ \\ \\____  \\ "
    "\\ \\____\n"
    " \\/\\_____\\    \\ \\_\\  \\ \\_____\\  \\ \\_\\ \\_\\  \\ \\_____\\  "
    "\\ \\_____\\\n"
    "  \\/_____/     \\/_/   \\/_____/   \\/_/\\/_/   \\/_____/   \\/_____/\n"
)


def search_stealer_name(text: str) -> StealerNameType | None:
    """Parse text file to find stealer name.

    Parameters
    ----------
    text : str
        The archive file's text content.

    Returns
    -------
    stealer_parser.models.types.StealerType or None
        The lowercase infostealer name if found. Otherwise, None.

    """
    # Search Redline first because it occurs the most.
    stealer_regex: str = (
        r"(?i)\b(redline|stealc|raccoon|lummac2)([^a-zA-Z]|\b)"
    )
    # Let's break down this regex:
    #
    # (?i)    Case insensitive
    # \b      Assert position at a word boundary: (^\w|\w$|\W\w|\w\W)
    # (redline|stealc|raccoon|lummac2)
    #         Match exact stealer name.
    # ([^a-zA-Z]|\b)
    #         Stealer name is followed by non-alphabetic characters or word
    #         boundary.
    matched: re.Match[str] | None = re.search(stealer_regex, text)

    if matched:
        return matched.group(1).lower()  # type: ignore

    clean_text: str = text.replace("\r\n", "\n")

    if REDLINE_HEADER in clean_text or REDLINE_HEADER_MALFORMED in clean_text:
        return "redline"

    if STEALC_HEADER in clean_text:
        return "stealc"

    if META_HEADER in clean_text:
        return "meta"

    if RACCOON_HEADER in clean_text:
        return "raccoon"

    if DCRAT_HEADER in clean_text:
        return "dcrat"

    return None
