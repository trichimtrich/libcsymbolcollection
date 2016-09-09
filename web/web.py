#!/usr/bin/python

# GNU LibC symbol collection - WebUI
# ver1.0
# trichimtrich

from flask import *
from pymongo import MongoClient
import json

client = MongoClient()
libc = client.libc
countlib = len(libc.collection_names())
app = Flask(__name__)


#same as console one, but query from mongodb (for less memory consuming)
def search_symbol(inputs, outputs):	
	hope = []
	for md5 in libc.collection_names():
		collect = libc.get_collection(md5).find_one()
		ar = collect['symbol']
		thisisit = True
		for sym, add in inputs:
			if ar.has_key(sym) and (ar[sym]&0xfff) != (add&0xfff):
				thisisit = False
				break
		if not thisisit: continue
		symbol = []
		for sym in outputs:
			if ar.has_key(sym): 
				symbol.append((sym, ar[sym], "0x%x" % ar[sym]))
			else:
				symbol.append((sym, -1))
		hope.append({	'name' : collect['name'],
						'hash' : collect['hash'],
						'arch' : collect['arch'],
						'desc' : collect['desc'],
						'symbol' : symbol})
	return hope


def query():
	args = request.args
	msg = "Me too :("
	hope = []
	if len(args)>0:
		ar_input = []
		ar_output = []
		for sym, value in args.iteritems():
			ar_output.append(sym)
			try:
				if value.isdigit(): value = int(value)
				else: value = int(value, 16)
			except: value = -1
			if value >= 0: ar_input.append((sym, value))

		if len(ar_input)>0:
			hope = search_symbol(ar_input, ar_output)
			if len(hope)>0:
				msg = "Total: %d" % len(hope)
			else:
				msg = "No libc matched :("
		else:
			msg = "Need at least one param \"symbol=<numeric string>\""
	else:
		pass
	return msg, hope

@app.route("/", methods=['GET', 'POST'])
@app.route("/index", methods=['GET', 'POST'])
def appindex():
	msg, hope = query()
	return render_template('web.html', web={"countlib" : countlib,
											"msg" : msg,
											"hope" : hope})

@app.route("/json", methods=['GET', 'POST'])
def appjson():
	msg, hope = query()
	return json.dumps(hope)

app.run(host="0.0.0.0", debug=False)