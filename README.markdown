Searchable encrypted database.

Based on the final scheme described by Dawn Song et al.[^song]

[^song]: Song, Dawn Xiaoding, David Wagner, and Adrian Perrig. "Practical
techniques for searches on encrypted data." In *Security and Privacy*, 2000.
S&P 2000.  Proceedings. 2000 IEEE Symposium on, pp. 44-55. IEEE, 2000.

## Requirements

-   Python 3.4 with development headers (e.g. `Python.h`)

    Install from source [at the Python
    website](https://www.python.org/ftp/python/3.4.0/Python-3.4.0.tgz)

## Setup

Setup the development environment by running the boostrap script.

    script/bootstrap

## Test

Use the provided test script to run unit tests.

    script/test

## Contributing

1.  Download this repository from GitHub and bootstrap the environment.

        git clone https://github.com/Pringley/edb
        cd edb
        script/bootstrap

2.  Fork this repository with the provided script.

        script/fork

    This creates your own personal version of the code on GitHub. Your changes
    will be applied to your own repo, then merged back in via a Pull Request
    (see below).

3.  Make each logical set of changes in a separate feature branch.

    You can use the following shortcut script to create feature branches from
    the latest `master`:

        script/newfeature NEWBRANCHNAME

    Make a commit for each individual change. Your commits will be saved to
    your local `NEWBRANCH`.

        git add changed_file1 changed_file2
        git commit --message="SUMMARY OF CHANGES"

4.  When your feature is complete, push your changes back to GitHub with the
    following commands:

        git push origin NEWBRANCH
        script/pullrequest NEWBRANCH
