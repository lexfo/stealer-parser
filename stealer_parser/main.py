"""Infostealer logs parser."""
from argparse import Namespace
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from py7zr import SevenZipFile
from rarfile import RarFile
from verboselogs import VerboseLogger

from stealer_parser.helpers import dump_to_file, init_logger, parse_options
from stealer_parser.models import ArchiveWrapper, Leak
from stealer_parser.processing import process_archive


def read_archive(
    buffer: BytesIO, filename: str, password: str | None
) -> ArchiveWrapper:
    """Open logs archive and returns a reader object.

    Parameters
    ----------
    buffer : io.BytesIO
        The opened archive stream.
    filename : str
        The archive filename.
    password : str
        If applicable, the password required to open the archive.

    Returns
    -------
    stealer_parser.models.archive_wrapper.ArchiveWrapper or None

    Raises
    ------
    NotImplementedError
        If the ZIP compression method or the file extension is not handled.
    rarfile.Error
        If either unrar, unar or bdstar binary is not found.
    py7zr.exceptions.Bad7zFile
        If the file is not a 7-Zip file.
    FileNotFoundError, OSError, PermissionError
        If the archive file is not found or can't be read.

    """
    archive: RarFile | ZipFile | SevenZipFile

    match Path(filename).suffix:
        case ".rar":
            archive = RarFile(buffer)

        case ".zip":
            archive = ZipFile(buffer)

        case ".7z":
            archive = SevenZipFile(buffer, password=password)

        case other_ext:
            raise NotImplementedError(f"{other_ext} not handled.")

    return ArchiveWrapper(archive, filename=filename, password=password)


def main() -> None:
    """Program's entrypoint."""
    args: Namespace = parse_options("Parse infostealer logs archives.")
    logger: VerboseLogger = init_logger(
        name="StealerParser", verbosity_level=args.verbose
    )
    archive: ArchiveWrapper | None = None

    try:
        leak = Leak(filename=args.filename)

        with open(args.filename, "rb") as file_handle:
            with BytesIO(file_handle.read()) as buffer:
                archive = read_archive(buffer, args.filename, args.password)
                process_archive(logger, leak, archive)

    except (
        FileNotFoundError,
        NotImplementedError,
        OSError,
        PermissionError,
    ) as err:
        logger.error(f"Failed reading {args.filename}: {err}")

    except RuntimeError as err:
        logger.error(f"Failed parsing {args.filename}: {err}")

    else:
        dump_to_file(logger, args.outfile, leak)

    finally:
        if archive:
            archive.close()


if __name__ == "__main__":
    main()
