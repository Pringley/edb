Searchable encrypted database.

Based on the final scheme described by Dawn Song et al.[^song]

[^song]: Song, Dawn Xiaoding, David Wagner, and Adrian Perrig. "Practical
techniques for searches on encrypted data." In *Security and Privacy*, 2000.
S&P 2000.  Proceedings. 2000 IEEE Symposium on, pp. 44-55. IEEE, 2000.

## Requirements

-   SQLite3 with development headers.

    Usually comes bundled with Python, except sometimes on Ubuntu. In that
    case, run:

        sudo apt-get update && sudo apt-get install libsqlite3-dev

-   Python 3.4 with development headers.

    The source is available [at the Python
    website](https://www.python.org/ftp/python/3.4.0/Python-3.4.0.tgz)

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
the required packages installed within.

## Test

Use the built-in Python unittest module to run the tests.

    venv/bin/python -m unittest test

## Contributing workflow

The following steps will work for users with push permissions on this
repository.

1.  Download this repository from GitHub and bootstrap the environment.

        git clone https://github.com/Pringley/edb.git
        cd edb
        python3.4 bootstrap.py

2.  Make each logical set of changes in a separate feature branch.

    Run the following commands to create a new feature branch (replace
    `NEWBRANCH` with the name of your feature):

        git fetch origin
        git checkout -b NEWBRANCH origin/master

    Make a commit for each individual change. Your commits will be saved to
    your local `NEWBRANCH`.

        git add changed_file1 changed_file2
        git commit --message="SUMMARY OF CHANGES"

4.  When your feature is complete, push your changes back to GitHub with the
    following commands:

        git push origin NEWBRANCH

    Then open a pull request by visiting the following URL:

    <https://github.com/Pringley/edb/compare/master...NEWBRANCH>

    The group will review the pull request before merging it into `master`.

### External contributors

If you don't have push permissions on this repo, you can still help out by
[forking](https://github.com/Pringley/edb/fork). This creates a copy of the
repository under your GitHub username.

1.  Instead of cloning the main repository, run:

        git clone https://github.com/YOURUSERNAME/edb
        git remote add upstream https://github.com/Pringley/edb.git

2.  Now you can create new branches using these commands:

        git fetch upstream
        git checkout -b NEWBRANCH upstream/master

3.  Once your changes are committed, push to your forked repo using:

        git push origin NEWBRANCH

    Pull requests can be opened from your repository by visiting:

    <https://github.com/YOURUSERNAME/edb/compare/Pringley:master...NEWBRANCH>
