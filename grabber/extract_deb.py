import sys, subprocess, os
from libc import libc_to_sym

if len(sys.argv)==1:
	print "Usage: python %s <scrape file>" % sys.argv[0]
	sys.exit(1)

if os.path.isdir("deb"): os.mkdir("deb")
if os.path.isdir("libc"): os.mkdir("libc")

c = 0
for url in open(sys.argv[1]):
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
	print "[+] %s" % libc_to_sym("libc/" + bn + ".so", "libc/" + bn + ".sym", bn, url)
