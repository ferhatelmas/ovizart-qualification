import sys

from scapy.all import rdpcap, IP


def do_q1(ifile, ofile):
    pckts = rdpcap(ifile)
    conns, total = {}, len(pckts)
    for p in [p[IP] for p in pckts]:
        conn = (p.src, p.dst)
        conns[conn] = conns.get(conn, 0) + 1.0

    with open(ofile, 'w') as f:
        f.write("source,target,value\n")
        for k, v in conns.items():
            f.write("%s,%s,%f\n" % (k[0], k[1], v/total))

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print "Usage: q1.py capture-file csv-file"
    else:
        do_q1(sys.argv[1], sys.argv[2])
