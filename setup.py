from setuptools import setup, find_packages
from glob import glob

setup(
    name = "logdb",
    version = "0.0.1",
    packages = ['logdb', 'edb'],
    scripts = [
        'scripts/client',
        'scripts/server',
    ],

    url = "https://github.com/Pringley/mpass-python",
    
    author = "Ben Pringle, Adil Soubki, Drew McGowen",
    author_email = "ben.pringle@gmail.com",
    description = "Encrypted packet log database",
    license = "MIT",
)
