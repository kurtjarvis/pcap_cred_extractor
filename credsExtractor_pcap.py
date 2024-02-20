#!/usr/bin/env python3

import pyshark
import argparse
from pathlib import Path

# loads single pcap into all of its frames
def parsePcap(pcap):
    frames = pyshark.FileCapture(pcap) #initialize
    frames.load_packets()
    return frames

#python def for main
def main():
    # Set up the arguments
    parser = argparse.ArgumentParser(description="pcap parser")
    parser.add_argument('-p', '--pcap_file', help="PCAP filename to read in and parse",
                        nargs='+')
    options = parser.parse_args()
    for pcap in options.pcap_file:
        myPath = Path(pcap)
        if not myPath.is_file(): 
            print("Unable to find %s, please check the file path" % pcap)
            continue
        if pcap:
            frames = parsePcap(pcap)
            for frame in frames:
                if hasattr(frame, "frame_info"):
                    if "kerberos" in frame.frame_info.protocols:
                        kerb = frame['kerberos']
                        if hasattr(kerb, 'etype') and hasattr(kerb, 'cipher') and kerb.msg_type == '10' and kerb.enctype == "18":
                            # So this is a kerberos request, let's pull out the cipher
                            print("Found a request for user %s\%s" % (kerb.realm, kerb.cnamestring))
                            print("$krb5pa$%s$%s$%s$%s" % (kerb.enctype, kerb.cnamestring, kerb.realm, kerb.cipher.translate( {ord(":"): None})))

# Main instaciation
if __name__ == "__main__":
   main()