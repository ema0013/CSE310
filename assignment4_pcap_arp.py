import dpkt
import struct

hardwares = {b'\x00\x00': "Reserved",
             b'\x00\x01': "Ethernet",
             b'\x00\x02': "Experimental Ethernet",
             b'\x00\x03': "Amateur Radio",
             b'\x00\x04': "Proteon ProNET Token Ring"}
protocols = {b'\x08\x00': "IPv4"}
op_codes = {b'\x00\x00': "Reserved",
            b'\x00\x01': "Request",
            b'\x00\x02': "Reply"}


def main():
    file = open('assignment4_my_arp.pcap', 'rb')
    pcap = dpkt.pcap.Reader(file)
    arps = list()
    for ts, buf in pcap:
        if buf[12:14] == b'\x08\06':
            arps.append(buf)
    arp_exchange = (arps[0], arps[1])
    print('ARP Exchange: \nSender:'
          '\nHardware Type:', int.from_bytes(arp_exchange[0][14:16], 'big', signed=False), hardwares.get(arp_exchange[0][14:16]),
          '\nProtocol Type:', arp_exchange[0][16:18], protocols.get(arp_exchange[0][16:18]),
          '\nHardware Size:', int.from_bytes(arp_exchange[0][18:19], 'big', signed=False),
          '\nProtocol Size:', int.from_bytes(arp_exchange[0][19:20], 'big', signed=False),
          '\nOpcode:', int.from_bytes(arp_exchange[0][20:22], 'big', signed=False), op_codes.get(arp_exchange[0][20:22]),
          '\nSender MAC Address:', "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", arp_exchange[0][22:28]),
          '\nSender IP Address:', "%x.%x.%x.%x" % struct.unpack("BBBB", arp_exchange[0][28:32]),
          '\nTarget MAC Address:', "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", arp_exchange[0][32:38]),
          '\nTarget IP Address:', "%x.%x.%x.%x" % struct.unpack("BBBB", arp_exchange[0][38:42]))
    print('Receiver:',
          '\nHardware Type:', int.from_bytes(arp_exchange[1][14:16], 'big', signed=False), hardwares.get(arp_exchange[1][14:16]),
          '\nProtocol Type:', arp_exchange[1][16:18], protocols.get(arp_exchange[1][16:18]),
          '\nHardware Size:', int.from_bytes(arp_exchange[1][18:19], 'big', signed=False),
          '\nProtocol Size:', int.from_bytes(arp_exchange[1][19:20], 'big', signed=False),
          '\nOpcode:', int.from_bytes(arp_exchange[1][20:22], 'big', signed=False), op_codes.get(arp_exchange[1][20:22]),
          '\nSender MAC Address:', "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", arp_exchange[1][22:28]),
          '\nSender IP Address:', "%x.%x.%x.%x" % struct.unpack("BBBB", arp_exchange[1][28:32]),
          '\nTarget MAC Address:', "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", arp_exchange[1][32:38]),
          '\nTarget IP Address:', "%x.%x.%x.%x" % struct.unpack("BBBB", arp_exchange[1][38:42]))


if __name__ == "__main__":
    main()
