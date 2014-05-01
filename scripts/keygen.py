from sys import argv
from edb.client import Client
from edb.crypto import generate_keyinfo, write_keyinfo

def main():
    if len(argv) != 2:
        print('Usage: keygen.py filename')
        return
    filename = argv[1]
    keyinfo = generate_keyinfo(Client.KEY_SCHEMA)
    write_keyinfo(keyinfo, filename)

if __name__ == '__main__':
    main()
