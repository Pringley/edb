import os

import requests
import click
import prettytable

from edb import crypto
from edb.client import Client as EDBClient
from edb.errors import EDBError

def run_cli():
    try:
        cli(obj={})
    except EDBError as err:
        print('Error:', err)

@click.group()
@click.option('--host', default='localhost',
        help='hostname of the server (default localhost)')
@click.option('--port', default=8000,
        help='port of the server')
@click.option('-k', '--keyfile', default='keyfile.json',
        help='path to the keyfile (default "keyfile.json")')
@click.pass_context
def cli(context, host, port, keyfile):
    """Client command line interface.

    To view help for a subcommand, run:

        client SUBCOMMAND --help
    
    """
    if context.invoked_subcommand not in ('keygen'):
        if keyfile == 'keyfile.json' and not os.path.exists(keyfile):
            print('The client requires a keyfile to proceed.')
            print('Generate using the `keygen` command.')
            context.exit()
        context.obj['client'] = Client(keyfile=keyfile, host=host, port=port)

@cli.command()
@click.argument('filename', default='keyfile.json',
        help='destination filename (optional)')
@click.pass_context
def keygen(context, filename):
    """Generate client keys."""
    keyinfo = crypto.generate_keyinfo(EDBClient.KEY_SCHEMA)
    crypto.write_keyinfo(keyinfo, filename)
    print('Created keyfile at {}'.format(os.path.abspath(filename)))

@cli.command()
@click.option('-s', '--source', help='filter by source IP')
@click.option('-d', '--destination', help='filter by destination IP')
@click.option('-p', '--protocol', help='filter by protocol IP')
@click.pass_context
def lookup(context, source, destination, protocol):
    """Look up packets in the database."""
    client = context.obj['client']
    params = {}
    if source: params['source'] = source.encode()
    if destination: params['destination'] = destination.encode()
    if protocol: params['protocol'] = protocol.encode()
    results = client.search(**params)
    fields = ('source', 'destination', 'protocol', 'length')
    table = prettytable.PrettyTable(fields)
    for result in results:
        row = []
        for field in fields:
            cell = result[field]
            if isinstance(cell, (bytes, bytearray)):
                try:
                    cell = cell.decode()
                except:
                    cell = ''
            row.append(cell)
        table.add_row(row)
    print(table)

@cli.command()
@click.argument('source', help='source IP address')
@click.argument('destination', help='destination IP address')
@click.argument('protocol', help='packet protocol')
@click.argument('length', help='packet length')
@click.pass_context
def add(context, source, destination, protocol, length):
    """Add a row to database."""
    client = context.obj['client']
    client.create(source=source.encode(),
                  destination=destination.encode(),
                  protocol=protocol.encode(),
                  length=length)

@cli.command()
@click.argument('filename', type=click.File('r'),
        help='data file')
@click.pass_context
def addfrom(context, filename):
    """Add rows from file.

    The file format is simple: one row per line, with fields separated by
    spaces.

    """
    client = context.obj['client']
    for line in filename:
        try:
            source, destination, protocol, length = line.strip().split()
        except ValueError:
            print('Warning: skipping invalid line:', repr(line))
        client.create(source=source.encode(),
                      destination=destination.encode(),
                      protocol=protocol.encode(),
                      length=length)
    print('Added files. Use `lookup` to view.')

@cli.command()
@click.option('-s', '--source', help='filter by source IP')
@click.option('-d', '--destination', help='filter by destination IP')
@click.option('-p', '--protocol', help='filter by protocol IP')
@click.pass_context
def average(context, source, destination, protocol):
    """Compute average message length."""
    client = context.obj['client']
    params = {}
    if source: params['source'] = source.encode()
    if destination: params['destination'] = destination.encode()
    if protocol: params['protocol'] = protocol.encode()
    print(client.average(**params))

@cli.command()
@click.option('-s', '--source', help='filter by source IP')
@click.option('-d', '--destination', help='filter by destination IP')
@click.option('-p', '--protocol', help='filter by protocol IP')
@click.pass_context
def count(context, source, destination, protocol):
    """Count messages matching a query."""
    client = context.obj['client']
    params = {}
    if source: params['source'] = source.encode()
    if destination: params['destination'] = destination.encode()
    if protocol: params['protocol'] = protocol.encode()
    print(client.count(**params))

@cli.command()
@click.argument('source', help='the source IP address')
@click.argument('destination', help='the destination IP address')
@click.pass_context
def correlate(context, source, destination):
    """Compute correlation between IPs."""
    client = context.obj['client']
    print(client.correlate(source.encode(), destination.encode()))

class Client(EDBClient):

    def __init__(self, keyfile=None, host=None, port=None):
        super(self.__class__, self).__init__(keyfile)
        self.host = host or 'localhost'
        self.port = port or 8000
        self.url = 'http://{}:{}/'.format(self.host, self.port)
        self.packet_url = self.url + 'packets/'
        self.count_url = self.url + 'compute/count/'
        self.average_url = self.url + 'compute/average/'
        self.correlate_url = self.url + 'compute/correlate/'

    def request(self, method, *args, **kwargs):
        resp = requests.request(method, *args, **kwargs)
        try:
            resp = resp.json()
        except:
            raise EDBError('received invalid response from server')
        if 'detail' in resp:
            raise EDBError(detail)
        return resp

    def search(self, **query):
        encrypted_query = self.encrypt_query(query)
        resp = self.request('get', self.packet_url, params=encrypted_query)
        return [self.decrypt_model(model, paillier_fields=['length'],
                exclude_fields=['id'])
                for model in resp]

    def create(self, **model):
        encrypted_model = self.encrypt_model(model, paillier_fields=['length'])
        self.request('post', self.packet_url, data=encrypted_model)

    def correlate(self, source, destination):
        params = self.encrypt_query({'source': source, 'destination': destination})
        resp = self.request('get', self.correlate_url, params=params)
        try:
            return float(resp['coefficient'])
        except (ValueError, KeyError):
            raise EDBError('received invalid response from server')

    def count(self, **query):
        params = self.encrypt_query(query)
        resp = requests.get(self.count_url, params=params).json()
        try:
            return int(resp['count'])
        except (ValueError, KeyError):
            raise EDBError('received invalid response from server')

    def average(self, **query):
        params = self.encrypt_query(query)
        key = self.keys['paillier']
        params.update(modulus=str(key.modulus), generator=str(key.generator))
        resp = self.request('get', self.average_url, params=params)
        if 'count' not in resp or 'sum' not in resp:
            raise EDBError('received invalid response from server')
        count = self.paillier_decrypt(resp['count'])
        total = self.paillier_decrypt(resp['sum'])
        return (total / count) if count != 0 else 0
