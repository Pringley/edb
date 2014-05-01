#Query.py
import sys
import pprint
from logdb.client import Client

def main():
	if (len(sys.argv) < 3):
		print("Usage: query.py source_IP, dest_IP, protocol, length, passphrase")
		print("If you wish to ommit a field enter null")
		sys.exit()
	query = {}
	if (sys.argv[1] != 'null'):
		query['source'] = sys.argv[1].encode()
	if (sys.argv[2] != 'null'):
		query['destination'] = sys.argv[2].encode()
	if (sys.argv[3] != 'null'):
		query['protocol'] = sys.argv[3].encode()
	if (sys.argv[4] != 'null'):
		query['length'] = sys.argv[4]
	if (sys.argv[5] == 'null'):
		print("You must enter a passphrase!")
		sys.exit()
	passphrase = sys.argv[5]
	c = Client(passphrase)
	print("Database entries for query: " + str(query))
	pprint.pprint(c.search(**query))

main()


