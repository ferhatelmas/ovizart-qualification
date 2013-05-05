from lib.dissector import *


def do_q3(ifile, ofile):
    pckts = "\n".join(Dissector().dissect_pkts(ifile)['irc'])
    with open(ofile, 'w') as f:
        f.write(pckts)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print "Usage: q3.py capture-file output-file"
    else:
        do_q3(sys.argv[1], sys.argv[2])
