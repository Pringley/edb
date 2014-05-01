from logdb.client import Client
import sys

def file_len(fname):
	with open(fname) as f:
		i = 0
		for line in f:
			for word in line.split():
				i = i+1
	return i

def parse_lines(fname):
	data = []
	with open(fname ,'r') as f:
		for line in f:
			if (len(line.split()) != 0):
				data.append(line.split())
	for i in range(0, len(data)):
		for j in range (0, len(data[i])):
			data[i][j] = data[i][j].encode()
	return data

def Populate(client):
	c = client
	data = parse_lines("EDB_Test_Data.txt")
	parameters = ["source", "destination", "protocol", "length"]
	for i in range(0, len(data)):
		print(data[i])
		c.create(**dict(zip(parameters, data[i])))

def main():
	if len(sys.argv) != 2:
		print("Usage: populate.py keyfile")
		sys.exit()
	keyfile = sys.argv[1]
	c = Client(keyfile)
	Populate(c)

main()
