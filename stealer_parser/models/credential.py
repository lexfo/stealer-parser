"""Data model to define user credentials found in leaks."""
import re
from dataclasses import dataclass
from urllib.parse import ParseResult, ParseResultBytes, urlparse

from .types import StealerNameType


@dataclass
class Credential:
    """Class defining a credential.

    Attributes
    ----------
    software : str, optional
        Used software like web browser or email client.
    host : str, optional
        Hostname or URL visited by user.
    username : str, optional
        Username or email address used to login.
    password : str, optional
        Password.
    domain : str, optional
        Domain name extracted from host/URL.
    local_part : str, optional
        The part before the @ in an email address.
    email_domain : str, optional
        Domain name extracted from email address.
    filepath : str, optional
        The credential file path.
    stealer_name : stealer_parser.models.types.StealerType, optional
        If applicable, the stealer that harvested the data.

    """

    software: str | None = None
    host: str | None = None
    username: str | None = None
    password: str | None = None
    domain: str | None = None
    local_part: str | None = None
    email_domain: str | None = None
    filepath: str | None = None
    stealer_name: StealerNameType | None = None


NORM_TEXT_PATTERN: re.Pattern[str] = re.compile(r"[\[\]\"']")
EMAIL_PATTERN: re.Pattern[str] = re.compile(r"\b(\S+)@(\S+\.\S+)\b")


def normalize_credential_text(credential: Credential) -> None:
    """Clean credential's text attributes.

    Parameters
    ----------
    credential : stealer_parser.models.credential.Credential
        The credential object to update.

    """
    if credential.software:
        software: str = NORM_TEXT_PATTERN.sub("", credential.software.lower())
        credential.software = software.replace("_", " ")


def split_credential_email(credential: Credential) -> None:
    """Extract email domain from credential's email address.

    Parameters
    ----------
    credential : stealer_parser.models.credential.Credential
        The credential object to update.

    """
    if not credential.username:
        return

    email_address: re.Match[str] | None = EMAIL_PATTERN.match(
        credential.username
    )

    if email_address:
        credential.local_part = email_address.group(1)
        credential.email_domain = email_address.group(2)


def extract_credential_domain_name(credential: Credential) -> None:
    """Extract domain name from credential's URL.

    Parameters
    ----------
    credential : stealer_parser.models.credential.Credential
        The credential object to update.

    """
    if not credential.host:
        return

    url: ParseResult | ParseResultBytes = urlparse(credential.host)

    if isinstance(url, ParseResult):
        if url.hostname:
            credential.domain = url.hostname
