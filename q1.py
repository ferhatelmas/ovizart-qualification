from os.path import splitext
import sys

try:
    from scapy.all import IP, rdpcap
except ImportError as e:
    sys.stderr.write("Error: failed to import rdpcap and IP ({})\n".format(e))
    sys.exit(0)


def generate_frequency_csv(ifile, ofile):
    """Generate a comma separated .csv file from a traffic capture
       for communication frequency of the IP addresses.

    Args:
        ifile (str): path for the traffic capture to be analyzed
        ofile (str): path of the output file for results to be written
    Returns:
        None but generates a file as a side effect.
        File format: source,target,value where value is in [0, 1]
        The higher the value is, the more frequent communication between nodes is
    """
    try:
        packets = rdpcap(ifile)
    except IOError as e:
        sys.stderr.write("Error: failed to read and dissect the capture ({})\n".format(e))
        return

    ip_layers = [packet[IP] for packet in packets if packet.haslayer(IP)]
    conn_freq, total_connections = ({}, float(len(ip_layers)))
    for ip in ip_layers:
        conn = (ip.src, ip.dst)
        conn_freq[conn] = conn_freq.get(conn, 0) + 1

    desired_extension = '.csv'
    file_name, file_extension = splitext(ofile)
    if file_extension != desired_extension:  # check output file extension
        print "Warning: output file name doesn't contain {} extension".format(
            desired_extension)
        ofile = file_name + desired_extension  # force desired extension

    try:
        with open(ofile, 'w') as f:
            f.write("source,target,value\n")  # write header
            for (client, server), cnt in conn_freq.items():
                f.write("%s,%s,%f\n" % (client, server, cnt/total_connections))
    except EnvironmentError as e:
        sys.stderr.write("Error: failed to write results ({})\n".format(e))
    else:
        print "Info: frequency results are successfully written to {}".format(ofile)


if __name__ == '__main__':
    argc = len(sys.argv)
    if argc < 3:
        print "Usage: q1.py input-capture-file output-csv-file"
    else:
        if argc > 3:
            print "Warning: unnecessary arguments ({})".format(" ".join(sys.argv[3:]))
        generate_frequency_csv(sys.argv[1], sys.argv[2])
