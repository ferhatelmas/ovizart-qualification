import sys

from scapy.all import rdpcap, IP, TCP


def do_q4(ifile, ofile):
    pckts = rdpcap(ifile)
    flags, chksums = {}, {}
    for i, p in enumerate(pckts):
        if TCP in p:
            ip = p[IP]
            tcp = ip[TCP]
            if (ip.src, ip.dst) in flags:
                if tcp.seq < flags[(ip.src, ip.dst)]:
                    print "Suspected frame %d with sequence number %s" % (i+1, tcp.seq)
            flags[(ip.dst, ip.src)] = tcp.ack

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print "Usage: q4.py capture-file output-file"
    else:
        do_q4(sys.argv[1], sys.argv[2])
