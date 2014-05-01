Searchable encrypted database.

## Requirements

-   Python 3.4 with development headers and SQLite3 support.

    The source is available [at the Python
    website](https://www.python.org/ftp/python/3.4.0/Python-3.4.0.tgz).

    To install from source, download from the link above and run:

        tar xzf Python-3.4.0.tgz
        cd Python-3.4.0
        ./configure
        make
        sudo make install

## Setup

Then setup the development environment by running the boostrap script provided
with this project.

    git clone https://github.com/Pringley/edb.git
    cd edb
    python3.4 bootstrap.py

This will create a [virtual environment](http://virtualenv.org) in `venv/` with
the required packages installed within. It should also configure the server's
database.

## Usage

Start the virtual environment using:

    source venv/bin/activate

This should prepend `(venv)` to your prompt and activate the EDB commands.

>   **Note:** this only activates the commands *in the current terminal
>   session*. If you use multiple sessions (such as one for the client and one
>   for the server), you ust run `source venv/bin/activate` in each.

Run the server using:

    server

This starts the server running at <http://localhost:8000>. You can visit it in
a web browser to debug!

Set up the client by generating keys.

    client keygen

Then add some test data to the server.

    client addfrom EDB_Test_Data.txt

You can use your own data instead, provided that it follows the format
specified in `client addfrom --help`.

The `client` script is well documented. Use `--help` to learn about its
available subcommands.

> **Usage:** `client [OPTIONS] COMMAND [ARGS]...`
>
> Client command line interface.
>
> To view help for a subcommand, run:
>
>     client SUBCOMMAND --help
>
> Commands:
>
> *   `add`        - Add a row to database.
> *   `addfrom`    - Add rows from file.
> *   `average`    - Compute average message length.
> *   `correlate`  - Compute correlation between IPs.
> *   `count`      - Count messages matching a query.
> *   `keygen`     - Generate client keys.
> *   `lookup`     - Look up packets in the database.
>
> Options:
>
> *   `--host=HOST`           - hostname of the server (default localhost)
> *   `--port=PORT`           - port of the server (default 8000)
> *   `--keyfile=KEYFILE`     - path to the keyfile (default "keyfile.json")
> *   `--help`                - Show this message and exit.

For example, running `client lookup` attempts to decrypt all rows in the
database (not guaranteed to work).

    +-----------------+-----------------+-------------+--------+
    |      source     |   destination   |   protocol  | length |
    +-----------------+-----------------+-------------+--------+
    |  111.221.77.158 |  129.161.75.51  |     TCP     |   57   |
    |  129.161.75.51  |  129.161.75.255 | DB-LSP-DISC |  195   |
    |  129.161.75.51  | 255.255.255.255 | DB-LSP-DISC |  195   |
    |  129.161.75.51  | 255.255.255.255 | DB-LSP-DISC |  195   |
    |  129.161.75.158 | 239.255.255.250 |     SSDP    |  175   |
    |  129.161.75.158 | 239.255.255.250 |     SSDP    |  175   |
    |  129.161.75.158 | 239.255.255.250 |     SSDP    |  175   |
    |  129.161.75.51  |  192.168.1.103  |     SNMP    |  121   |
    |  174.137.42.75  |  129.161.75.51  |     TCP     |   66   |
    |  174.137.42.75  |  129.161.75.51  |     TCP     |   66   |
    | 162.159.242.165 |  129.161.75.51  |     TCP     |   66   |
    | 162.159.242.165 |  129.161.75.51  |     TCP     |   54   |
    | 141.101.116.148 |  129.161.75.51  |     TCP     |   54   |
    | 141.101.116.148 |  129.161.75.51  |     TCP     |   66   |
    | 141.101.116.148 |  129.161.75.51  |     TCP     |   66   |
    +-----------------+-----------------+-------------+--------+

You can also filter by using command options:

    client lookup --protocol TCP

Use the `count` command to get the total number of messages from (or to) an
address:

    client count --source 162.159.242.165

The `average` command asks the server to compute the average message length for
a given query.

    client average --source 129.161.75.51 --destination 255.255.255.255

## Test

To run the tests, execute the following command:

    venv/bin/python manage.py test

## Scope

This implementation focuses on the **confidentiality of data on an untrusted
server.**

Given the server database file (stored in `db.sqlite3`), an attacker shouldn't
be able to glean any information about the data storted within (apart from the
number of records stored, obviously).

Each query naturally leaks some information to the server. Each search reveals
traffic analysis data (although the plaintexts are not revealed).

We essentially **ignored securing the transport layer.**

Our client and server use HTTP to communicate. To secure the transport layer,
we could simply use HTTPS. (This is typically configured on the host computer.)

## Crypto

Our database is built around the [searchable scheme created by Dawn Song et
al.](http://www.cs.berkeley.edu/~dawnsong/papers/se.pdf) (see Section 4.4).

Searchable fields are encrypted with Song et al.'s scheme.

Arithmetic fields are encrypted with the [Paillier
cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem).

## Code layout

The project package is `logdb/`. It relies on a support library we wrote called
`edb/`.

Our implementation of Song's scheme is primarily in
[`edb/client.py`](edb/client.py). Our encryption of Paillier is in `edb/paillier.py`.

The server uses [Django REST framework](http://www.django-rest-framework.org/)
to parse JSON queries and generate responses. The main driver code is in
`logdb/views.py`, with the notable addition of the crypto search backend in
`edb/server/util.py`.
