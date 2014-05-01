# Contributing

Below are instructions for team members. In the section after, there are
instructions for anyone to contribute.

## Contributing for team members

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
