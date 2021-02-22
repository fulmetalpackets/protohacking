#By Douglas McKee @fulmetalpackets
# requires python3, binwalk, numpy-1.19.4 and pyqtgraph-0.11.0

from scapy.all import *
from fake_proto import *
import socket, struct
import subprocess
import argparse
import os
import binwalk

#User defined function, different for each protocol disecting
def getData(packets):
    dataPayload = b''
    for p in packets:
        #Structures comes from fake_proto.py
        if Data in p:
            dataPayload = dataPayload + p[TCP][Header][Data].data
    return dataPayload

#Given byte stream, calculate Shannon Entropy
def entropy(data):
    e = 0
    counter = collections.Counter(data)
    l = len(data)
    for count in counter.values():
        # count is always > 0
        p_x = count / l
        e += - p_x * math.log2(p_x)

    return e

# main
parser = argparse.ArgumentParser()
parser.add_argument("pcapFile", help="pcap file containing the data string to parse")
parser.add_argument("-d","--datafile", help="The name of the file to save the data stream too")
parser.add_argument("-o","--outdir", help="The name of the directory to save results to")
args = parser.parse_args()

packets = rdpcap(args.pcapFile)
data = getData(packets)
datafile = "test.bin"
outdir = "data_test_out"
if args.datafile:
    datafile = args.datafile
if args.outdir:
    outdir = args.outdir

if not os.path.exists(outdir):
    os.makedirs(outdir)
fullpath = outdir + os.sep + datafile

f = open(fullpath, 'w+b')
f.write(data)
f.close()

#run file
print("Running file command on data ...")
file_call = subprocess.run(["file",fullpath], stdout=subprocess.PIPE)
f = open(outdir + os.sep + "file.txt", 'w')
f.write(file_call.stdout.decode("utf-8"))
f.close()
print("File Test: " + file_call.stdout.decode("utf-8"))  
#strings
print("Running strings command on data...")
strings_call = subprocess.run(["strings",fullpath], stdout=subprocess.PIPE)
f = open(outdir + os.sep + "strings.txt", 'w')
f.write(strings_call.stdout.decode("utf-8"))
f.close()
print("Strings saved to file.")  
#readelf
print("Running readelf command on data...")
readelf_call = subprocess.run(["readelf","-a",fullpath], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
f = open(outdir + os.sep + "readelf.txt", 'w')
f.write(readelf_call.stdout.decode("utf-8"))
f.close()
if readelf_call.stderr != None:
    print("Error occured: " + readelf_call.stderr.decode("utf-8"))
print("readelf output saved to file.")  
#Shannon entropy test 
print("Running Shannon entropy test on data...")
print("Data stream Shannon Entropy: " + str(entropy(data))) 
# binwalk entropy test
os.chdir(outdir)
print("Running binwalk on data...")
print("Binwalk signature Test")
for module in binwalk.scan(datafile, signature=True,quiet=True):
    print ("%s Results:" % module.name)
    for result in module.results:
        print ("\t%s    0x%.8X    %s" % (result.file.path, result.offset, result.description))

#binwalk signature 
print("Binwalk Entropy Test")
print("Binwalk Entropy image saved.")
bin_entropy = binwalk.scan(datafile, entropy=True,save=True)


