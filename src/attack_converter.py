import sys
import getopt
import json

def main(argv):
    inputFile = ''
    outputFile = ''
    ruleType = 'alert'
    try:
        opts, args = getopt.getopt(argv,"hsdi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print('test.py -i <inputfile> -o <outputfile>')
        sys.exit(2)
    includeSrc = False
    includeDst = False
    for opt, arg in opts:
        if opt == '-h':
            print('attack_converter.py -i <inputfile> -o <outputfile>')
            print('Add -s flag to include src_ips and ports')
            print('Add -d flag to include dst_ports')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputFile = arg
        elif opt in ("-o", "--ofile"):
            outputFile = arg
        elif opt == '-s':
            includeSrc = True
        elif opt == '-d':
            includeDst = True
    print('Input file is ' + inputFile)
    print('Output file is ' + outputFile)
    with open(inputFile) as f:
        inputData = json.load(f)
    protocol = inputData['protocol']
    srcIps = inputData['src_ips'] if includeSrc and len(inputData['src_ips']) > 0 else "any"
    srcPorts = inputData['src_ports'] if includeSrc and len(inputData['src_ports']) > 0 else "any"
    dstPorts = inputData['dst_ports'] if includeDst  and len(inputData['dst_ports']) > 0 else "any"
    if protocol == 'DNS':
        query = inputData['additional']['dns_query']
        rule = '{} {} {} {} -> $HOME_NET {} (msg:"DNS DDoS alert"; classtype:denial-of-service; content:{}; nocase;)'.format(ruleType, protocol, srcIps, srcPorts, dstPorts, query)
    elif protocol == 'ICMP':
        itype = inputData['additional']['icmp_type']
        rule = '{} {} {} {} -> $HOME_NET {} (msg:"ICMP DDoS alert"; classtype:denial-of-service; itype: {};)'.format(ruleType, protocol, srcIps, srcPorts, dstPorts, itype)
    elif protocol == 'UDP':
        rule = '{} {} {} {} -> $HOME_NET {} (msg:"UDP DDoS alert"; classtype:denial-of-service;)'.format(ruleType, protocol, srcIps, srcPorts, dstPorts)
    elif protocol == 'NTP':
        rule = '{} {} {} {} -> $HOME_NET {} (msg:"NTP DDoS alert"; classtype:denial-of-service;)'.format(ruleType, protocol, srcIps, srcPorts, dstPorts)
    elif protocol == 'IPv4':
        rule = '{} {} {} {} -> $HOME_NET {} (msg:"IPv4 DDoS alert"; classtype:denial-of-service;)'.format(ruleType, protocol, srcIps, srcPorts, dstPorts)
    elif protocol == 'QUIC':
        rule = '{} {} {} {} -> $HOME_NET {} (msg:"QUIC DDoS alert"; classtype:denial-of-service;)'.format(ruleType, protocol, srcIps, srcPorts, dstPorts)
    print(rule)
    with open(outputFile, "w+") as o:
        o.write(rule + "\r\n")

if __name__ == "__main__":
   main(sys.argv[1:])
