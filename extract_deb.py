import sys, subprocess, os, json, shutil, time
from libc import extract_symbol

if len(sys.argv) not in (2, 3):
	print "Usage: python %s <list new debs> [list old debs]" % sys.argv[0]
	sys.exit(1)

old_debs = []
new_debs = []

if len(sys.argv) == 3:
	for fn in open(sys.argv[2]):
		fn = fn.strip()
		if fn=="": continue
		old_debs.append(fn)

for fn in open(sys.argv[1]):
	fn = fn.strip()
	if fn =="": continue
	if fn not in old_debs:
		new_debs.append(fn)
		old_debs.append(fn)

if not os.path.isdir("deb"): os.mkdir("deb")
if not os.path.isdir("libc"): os.mkdir("libc")

print "Total new %d" % len(new_debs)

collects = {}
if os.path.exists("libc.sym"): 
	shutil.copyfile("libc.sym", "libc_%d.sym" % int(time.time()))
	collects = json.load(open("libc.sym", "rb"))
else:
	print "libc.sym is not exists!"
	sys.exit(1)

c = 0
for url in new_debs:
	url = url.strip()
	if not url.endswith('.deb'): continue
	fn = url[url.rfind('/')+1:]
	if not fn.startswith('libc'): continue
	bn = fn[:-4]
	c += 1
	print "[%d] URL: %s -> %s" % (c, url, fn)

	subprocess.call("wget %s -O deb/%s" % (url, fn), shell=True)
	subprocess.call("dpkg-deb -x deb/%s deb/%s" % (fn, bn), shell=True)
	subprocess.call("cp `find deb/%s -type l -name \"libc.so*\" | tail -n 1` libc/%s" % (bn, bn + ".so"), shell=True)
	subprocess.call("rm -rf deb/%s" % bn, shell=True)

	sofn = "libc/" + bn + ".so"
	name = bn
	desc = url
	if not os.path.exists(sofn):
		print "File %s not found" % sofn
		continue
	md5, sha1, sha256, arch, sym = extract_symbol(sofn)

	collects[md5] = {	'name' : name,
						'hash' : {'md5' : md5, 'sha1' : sha1, 'sha256' : sha256},
						'arch' : arch,
						'desc' : desc,
						'symbol' : sym}
	print "[+]", bn

json.dump(collects, open("libc.sym", "wb"))
open("grab_%d.txt" % int(time.time()), "wb").write("\n".join(old_debs))