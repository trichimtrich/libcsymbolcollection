from pymongo import MongoClient
import json
import sys

if len(sys.argv)==1:
	print "Usage: python %s <libc.sym file>" % sys.argv[0]
	sys.exit(1)

collects = json.load(open(sys.argv[1]))
print "Current collection: %d libs" % len(collects)

client = MongoClient() #authenticate if needed
client.drop_database("libc")
db = client.libc

i = 0
for key in collects:
	i += 1
	print "[%d] Doing %s" % (i, key)
	db.create_collection(key)
	db.get_collection(key).insert(collects[key], check_keys=False)

print "Success!"