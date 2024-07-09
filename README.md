# Infostealer logs parser

Information stealers are malwares that steal sensitive data, aka **logs**, to be sold in forums or shared in chat groups.

This tool takes a **logs archive**, parses it, and produces a JSON file.

## Table of Content

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Features

- Accepts the following **archive formats**: `.rar`, `.zip`, `.7z`.
  Please note that multi-parts ZIP files aren't handled yet.
- Parses files containing credentials and information about compromised systems.
- Outputs result as **JSON**.

### Result

The following data are extracted:

- [Credential](stealer_parser/models/credential.py)

  - **software**: Web browser or email client.
  - **host**: Hostname or URL visited by user.
  - **username**: Username or email address.
  - **password**: Password.
  - **domain**: Domain name extracted from host/URL.
  - **local_part**: The part before the @ in an email address.
  - **email_domain**: Domain name extracted from email address.
  - **filepath**: The credential file path.
  - **stealer_name**: The stealer that harvested the data.

- [System](stealer_parser/models/system.py)

  - **machine_id**: The device ID (UID or machine ID).
  - **computer_name**: The machine's name.
  - **hardware_id**: The hardware ID (HWID).
  - **machine_user**: The machine user's name.
  - **ip_address**: The machine IP address.
  - **country**: The machine's country code.
  - **log_date**: The compromission date.

### Parsing errors

If a file can't be parsed, it will be saved into the `logs` folder as well as a `<filename>.log` text file containing the parsing related error message.

## Requirements

- Python 3.10 or greater
- [`Poetry`](https://python-poetry.org/)

## Installation

1. Clone the repository including its submodules and change it to your working directory.

```console
$ git clone --recurse-submodules https://github.com/lexfo/stealer-parser
```

2. Install the project:

```console
$ poetry install
```

3. Activate the virtual environment:

```console
$ poetry shell
```

## Usage

```console
stealer_parser [-h] [-p ARCHIVE_PASSWORD] [-o FILENAME.json] [-v] filename

Parse infostealer logs archives.

positional arguments:
  filename              the archive to process (handled extensions: .rar, .zip, .7z)

options:
  -h, --help            show this help message and exit
  -p ARCHIVE_PASSWORD, --password ARCHIVE_PASSWORD
                        the archive's password if required
  -o FILENAME.json, --outfile FILENAME.json
                        the output file name (.json extension)
  -v, --verbose         increase logs output verbosity (default: info, -v: verbose, -vv: debug, -vvv: spam)
```

Basic use:

```console
$ stealer_parser myfile.rar
2024-07-08 13:37:00 - StealerParser - INFO - Processing: myfile.rar ...
2024-07-08 13:37:00 - StealerParser - INFO - Successfully wrote 'myfile.json'.
```

Use the verbose option to display extra information:

```console
$ stealer_parser -vvv myfile.zip
2024-07-08 13:37:00 - StealerParser - INFO - Processing: myfile.zip ...
2024-07-08 13:37:00 - StealerParser - DEBUG - Parsed 'myfile.zip' (983 systems).
2024-07-08 13:37:00 - StealerParser - INFO - Successfully wrote 'myfile.json'.
```

Open password-protected archives:

```console
$ stealer_parser myfile.zip --password mypassword
```

Choose output file name:

```console
$ stealer_parser myfile.zip --outfile results/foo.json
```

## Documentation

The grammars can be found in the [`docs` directory](docs).

## Contributing

If you want to contribute to development, please read these [guidelines](CONTRIBUTING.md).

## Acknowledgements

Lexing and parsing made easier thanks to [`PLY`](https://github.com/dabeaz/ply) by **David Beazley**.

## License

This project is licensed under [Apache License 2.0](LICENSE.md).
