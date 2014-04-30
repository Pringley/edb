import os
import os.path
import sys
import shutil
import tarfile
import platform
import tempfile
import subprocess

MIN_PYTHON_VERSION = (2, 7)

VENV_VERSION = "1.11.4"
VENV_DIR = "virtualenv-" + VENV_VERSION
VENV_ARCHIVE = VENV_DIR + ".tar.gz"
VENV_URL="https://pypi.python.org/packages/source/v/virtualenv/" + VENV_ARCHIVE

class NoSafeDownloader(RuntimeError):
    """Raised if powershell, curl, or wget not installed."""

def main():
    if sys.version_info < MIN_PYTHON_VERSION:
        print('ERROR: this script requires Python %s.%s or greater.' %
                MIN_PYTHON_VERSION)
        sys.exit(1)

    project_dir = os.path.dirname(os.path.abspath(__file__))

    # Set up the virtual environment.
    env_dir = os.path.join(project_dir, 'venv')
    if sys.version_info >= (3, 4):
        make_venv = make_venv_34_plus
    else:
        make_venv = make_venv_legacy
    if not make_venv(env_dir):
        print('Error creating virtual environment.')
        exit(1)

    # Download requirements with pip.
    pip = os.path.join(env_dir, 'bin', 'pip')
    requirements = os.path.join(project_dir, 'requirements.txt')
    if not shell_run(pip, 'install', '-I', '-r', requirements):
        print('Error installing requirements! Bootstrap failed.')
        sys.exit(1)

    venv_python = os.path.join(env_dir, 'bin', 'python')
    def venv_python_run(*args):
        """Run a Python command within our new venv."""
        return shell_run(venv_python, *args)

    os.chdir(project_dir)
    if not venv_python_run('manage.py', 'syncdb', '--noinput'):
        print('Error setting up the local server database.')
        sys.exit(1)

    print('Bootstrap successful.')

def make_venv_legacy(env_dir):
    """Create a virtual environment pre-3.4.

    If virtualenv is not installed, download a temporary one.

    """
    env_dir = os.path.abspath(env_dir)

    # Try using the virtualenv command, if installed.
    if check_cmd('virtualenv', '--version'):
        if not shell_run('virtualenv', '--python', sys.executable, 'venv'):
            return False
        return True

    # Otherwise, download virtualenv and run it.
    tmpdir = tempfile.mkdtemp()
    prev_dir = os.getcwd()
    try:
        os.chdir(tmpdir)
        target = os.path.join(tmpdir, VENV_ARCHIVE)
        try:
            safe_download(VENV_URL, target)
        except (NoSafeDownloader, subprocess.CalledProcessError):
            # If we can't download it, tell the user how to install.
            print('Setup requires virtualenv.')
            print('Install at http://virtualenv.org then rerun this script.')
            return False
        extract(VENV_ARCHIVE)
        os.chdir(os.path.join(tmpdir, VENV_DIR))
        if not python_run('virtualenv.py', env_dir):
            return False
    finally:
        os.chdir(prev_dir)
        shutil.rmtree(tmpdir)

    return True

def make_venv_34_plus(env_dir):
    """Create a virtual environment on 3.4+."""
    import venv
    venv.create(env_dir, with_pip=True, clear=True)
    return True

def python_run(*args):
    """Run a Python program using this version."""
    return shell_run(sys.executable, *args)

def shell_run(*args):
    """Run a program in a subprocess."""
    return subprocess.call(args) == 0

def extract(archive):
    """Extract a tar.gz to the current directory."""
    tar = tarfile.open(archive)
    try:
        tar.extractall()
    finally:
        tar.close()

def check_cmd(*args):
    """Check a command for existence."""
    devnull = open(os.path.devnull, 'wb')
    try:
        subprocess.check_call(args, stdout=devnull, stderr=devnull)
    except subprocess.CalledProcessError:
        return False
    finally:
        devnull.close()
    return True

def safe_download(url, target):
    """Attempt to safely download url, saving at target path.

    Requires powershell, curl, or wget. If none are installed, raise a
    NoSafeDownloader exception.

    Inspired by setuptools' ez_setup.py.

    """
    # Check for existence of powershell, curl, wget.
    if sys.platform == 'Windows' and check_cmd('powershell', '-Command', 'echo test'):
        cmd = ['powershell', '-Command',
            "(new-object System.Net.WebClient).DownloadFile"
            "({0!r}, {1!r})".format(url, target)]
    elif check_cmd('curl', '--version'):
        cmd = ['curl', url, '--silent', '--output', target]
    elif check_cmd('wget', '--version'):
        cmd = ['wget', url, '--quiet', '--output', target]
    else:
        raise NoSafeDownloader

    target = os.path.abspath(target)
    try:
        # Run chosen download command.
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        # If command fails, delete partial download before re-raising
        # the exception.
        if os.access(target, os.F_OK):
            os.unlink(target)
        raise

if __name__ == '__main__':
    main()
