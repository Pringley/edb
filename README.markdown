Proof of concept searchable encrypted database.

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

## Contributing

1.  [Fork this repository](https://github.com/Pringley/edb-concept/fork) on
    GitHub.

2.  Clone your version of the repository.

        git clone https://github.com/YOURUSERNAME/edb-concept

3.  Set the upstream to the original repository.

        git remote add upstream https://github.com/Pringley/edb-concept.git

    This allows you to update your master branch with the following command:

        git pull upstream master:master

4.  Develop in a separate feature branch. Create a new branch with:

        git checkout master
        git checkout -b NEWBRANCH

    Push your changes using:

        git push origin NEWBRANCH:NEWBRANCH

5.  Submit your changes for review as a
    [Pull Request](https://github.com/Pringley/edb-concept/compare).
