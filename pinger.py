#!/usr/bin/python2
import math
import socket
import os
import sys
import struct
import time
import select
import binascii
import argparse

ICMP_ECHO_REQUEST = 8

unreachable_errors = [
    "Destination network unreachable",
    "Destination host unreachable",
    "Destination protocol unreachable",
    "Destination port unreachable",
    "Fragmentation required, and DF flag set",
    "Source route failed",
    "Destination network unknown",
    "Destination host unknown",
    "Source host isolated",
    "Network administratively prohibited",
    "Host administratively prohibited",
    "Network unreachable for ToS",
    "Host unreachable for ToS",
    "Communication adminitratively prohibited",
    "Host precedence violation",
    "Precedence cutoff in effect"
]

ttl_errors = [
    "TTL expired in transit",
    "Fragment reassembly time exceeded"
]

def checksum(str):
    csum = 0
    countTo = (len(str) / 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(str[count+1]) * 256 + ord(str[count])
        csum = csum + thisVal
        csum = csum & 0xffffffffL
        count = count + 2
    if countTo < len(str):
        csum = csum + ord(str[len(str) - 1])
        csum = csum & 0xffffffffL
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        timeReceived = time.time()
        howLongInSelect = (timeReceived - startedSelect)
        if whatReady[0] == []: # Timeout
            return (0, "Request timed out")
        recPacket, addr = mySocket.recvfrom(1024)
        #Fill in start
        #Fetch the ICMP header from the IP packet
        ip_header = recPacket[0:20]
        (resp_type, res_code, resp_checksum, resp_id, resp_seq) = struct.unpack('bbHHh', recPacket[20:28])
        if not resp_id == ID:
            continue
        if resp_type== 0:
            (req_time,) = struct.unpack('d', recPacket[28:36])
            #Fill in end
            if (timeLeft - howLongInSelect) <= 0:
                return (0, "Request timed out")
            else:
                return (timeReceived - req_time, None)
        elif resp_type == 3:
            return (0, unreachable_errors[resp_code])
        elif resp_type == 11:
            return (0, ttl_errors[resp_code])
        else:
            return (0, "Unknown ICMP type/code: (%d, %d)" % (resp_type, resp_code))

def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    # Make a dummy header with a 0 checksum.
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)
    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
    #Convert 16-bit integers from host to network byte order.
    else:
        myChecksum = socket.htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    #Both LISTS and TUPLES consist of a number of objects
    #which can be referenced by their position number within the object

def doOnePing(destAddr, timeout):
    icmp = socket.getprotobyname("icmp")
    #SOCK_RAW is a powerful socket type. For more details see: http://sock-raw.org/papers/sock_raw
    #Fill in start
    #Create Socket here
    mySocket = socket.socket(family=socket.AF_INET,type=socket.SOCK_RAW,proto=socket.IPPROTO_ICMP)
    #Fill in end
    myID = os.getpid() & 0xFFFF  #Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    return delay

def simple_ping(host, count=10, timeout=1):
    #timeout=1 means: If one second goes by without a reply from the server,
    #the client assumes that either the client's ping or the server's pong is lost
    dest = socket.gethostbyname(host)
    print "Pinging " + dest + " using Python:"
    #Send ping requests to a server separated by approximately one second
    for i in range(count):
        delay = doOnePing(dest, timeout)
        print delay
        time.sleep(1)# one second
    return delay

def ping(destination, count=10, timeout=1000):
    address = socket.gethostbyname(destination)
    rtts = []
    transmitted = 0
    print('pinging %s (%s)...' % (destination, address))
    start = time.time()
    try:
        for i in range(1, count+1):
            transmitted = i
            (rtt, err) = doOnePing(address, timeout/1000.0)
            if not err:
                rtts.append(rtt)
                print('ping %s (%s): icmp_seq=%d, time=%.1fms' % (destination, address, i, rtt*1000))
                time.sleep(max(0, timeout/1000.0-rtt))
            else:
                print('ping %s (%s) FAILED: icmp_seq=%d, error=%s' % (destination, address, i, err))
    except KeyboardInterrupt:
        pass
    end = time.time()
    print
    print('--- %s ping statistics ---' % (destination))
    print('%d packets transmitted, %d packets received, %d%% packet loss, time %dms' %
            (transmitted, len(rtts), (transmitted-len(rtts))*100/transmitted, (end-start)*1000))
    if len(rtts) > 0:
        mdev = math.sqrt(sum(map(lambda x: x**2, rtts))/len(rtts) - (sum(rtts)/len(rtts))**2)
        time_stats = (min(rtts)*1000, max(rtts)*1000, sum(rtts)/len(rtts)*1000, mdev*1000)
    else:
        time_stats = (0, 0, 0, 0)
    print('rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms' % time_stats)

if __name__ == "__main__":
    if not os.geteuid() == 0:
        sys.exit('Only root can run this script')
    parser = argparse.ArgumentParser(description='measure network latency and other basic connection metrics (ping)')
    parser.add_argument('destination', type=str, help='address of computer to ping')
    parser.add_argument('-c', '--count', metavar='count', dest='count', default=10, type=int, help='count')
    parser.add_argument('-t', '--timeout', metavar='timeout', dest='timeout', default=1000, type=int, help='timeout (ms)')
    args = parser.parse_args()
    ping(args.destination, count=args.count, timeout=args.timeout)
