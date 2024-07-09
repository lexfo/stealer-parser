"""Wrapper to manipulate several types of archive."""
import posixpath
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from py7zr import SevenZipFile
from py7zr.exceptions import CrcError
from rarfile import RarFile


class ArchiveWrapper:
    """Class defining a common interface for RAR, ZIP and 7z files.

    Attributes
    ----------
    root : rarfile.RarFile or zipfile.ZipFile or py7zr.SevenZipFile
        The archive's root directory.
    at : str, default=''
        The current archive member.
    filename : str, optional
        The archive's filename if not already set.
    password : str, optional
        The archive's password if required.
    _repr : str, optional
        The formatting string for the object's printable representation.

    Methods
    -------
    _is_child(path)
    _next(at)
    is_closed()
        Return True if the archive is closed.
    is_dir()
        Return True if the path points to a directory.
    close()
        Close the underlying archive object.
    namelist()
        Return names of the archive members.
    read_file(filename)
        Retrieve an archive file's text content.

    """

    _repr: str = (
        "{self.__class__.__name__}({self.root.filename!r}, {self.at!r})"
    )

    def __init__(
        self,
        root: RarFile | ZipFile | SevenZipFile,
        at: str = "",
        filename: str | None = None,
        password: str | None = None,
    ) -> None:
        """Initialize wrapper.

        Parameters
        ----------
        root : rarfile.RarFile or zipfile.ZipFile or py7zr.SevenZipFile
            The archive's root directory.
        at : str, default=''
            The current archive member.
        filename : str, optional
            The archive's filename if not already set.
        password : str, optional
            The archive's password if required.

        Raises
        ------
        ValueError
            If the archive root misses a filename or is closed.

        """
        self.root: RarFile | ZipFile | SevenZipFile = root
        self.at: str = at
        self.password = password

        if filename:
            self.root.filename = filename

        elif not self.root.filename:
            raise ValueError("Missing archive's name.")

        if password and not isinstance(self.root, SevenZipFile):
            self.root.setpassword(bytes(password, encoding="utf-8"))

    def __str__(self) -> str:  # noqa: D105
        return posixpath.join(self.root.filename, self.at)  # type: ignore

    def __repr__(self) -> str:  # noqa: D105
        return self._repr.format(self=self)

    # Properties ##############################################################

    @property
    def name(self) -> str:
        """Return the final path component."""
        return Path(self.at).name or self.filename.name

    @property
    def filename(self) -> Path:
        """Return the complete path."""
        return Path(self.root.filename).joinpath(self.at)  # type: ignore

    # Methods #################################################################

    def _is_child(self, path: "ArchiveWrapper") -> bool:
        return posixpath.dirname(path.at.rstrip("/")) == self.at.rstrip("/")

    def _next(self, at: str) -> "ArchiveWrapper":
        return self.__class__(self.root, at)

    def is_closed(self) -> bool:
        """Return True if the archive is closed."""
        if isinstance(self.root, SevenZipFile):
            return not self.root._fileRefCnt

        if isinstance(self.root, ZipFile):
            return not self.root.fp

        # RarFile
        if isinstance(self.root._rarfile, BytesIO):
            return self.root._rarfile.closed

        # NOTE: In case of Path object, will always return False because of
        # RarFile implementation.
        return not self.root._rarfile

    def is_dir(self) -> bool:
        """Return True if the path points to a directory."""
        return not self.at or self.at.endswith("/")

    def close(self) -> None:
        """Close the underlying archive object."""
        if isinstance(self.root, RarFile) and isinstance(
            self.root._rarfile, BytesIO
        ):
            self.root._rarfile.close()

        elif not self.is_closed():
            self.root.close()

    def namelist(self) -> list[str]:
        """Return names of the archive members."""
        # ZipInfo and RarInfo appends a slash to identify directories from
        # files. The following code adds it manually for 7z files.
        if isinstance(self.root, SevenZipFile):
            return [
                f"{elem.filename}/" if elem.is_directory else elem.filename
                for elem in self.root.files
            ]

        else:
            return self.root.namelist()

    def read_file(self, filename: str) -> str:
        """Retrieve an archive file's text content.

        Parameters
        ----------
        filename : str
            The file name to read.

        Returns
        -------
        str
            The file's text content.

        Raises
        ------
        KeyError
            If the file doesn't exist in the archive.
        NotImplementedError
            If the file uses a compression method other than ZIP_STORED,
            ZIP_DEFLATED, ZIP_BZIP2 or ZIP_LZMA.
        RuntimeError
            If the archive was closed.
        UnicodeDecodeError
            If all attemps to read the file with different encodings failed.
        ValueError
            If the file is a directory.
        py7zr.exceptions.CrcError
            Decompression error.

        """
        file_bytes: bytes = bytes()
        text: str = ""

        try:
            if isinstance(self.root, SevenZipFile):
                # SevenZipFile.read() takes a list of string and return a dict.
                texts: dict[str, BytesIO] = self.root.read([filename])
                self.root.reset()  # To avoid py7zr.exceptions.CrcError.

                with texts[filename] as buffer:
                    file_bytes = buffer.getvalue()

            else:
                file_bytes = self.root.read(filename)

            try:
                text = file_bytes.decode(encoding="utf-8")

            except UnicodeDecodeError:
                text = file_bytes.decode(encoding="utf-8", errors="ignore")

            return text.replace("\x00", "\\00")

        except KeyError as err:
            raise KeyError("Not found.") from err

        except AttributeError as err:
            raise RuntimeError(f"Missing attribute: '{err}'.") from err

        except ValueError as err:  # ZIP and RAR raise ValueError.
            raise RuntimeError(err) from err

        except CrcError as err:
            raise CrcError("Decompression error.") from err
