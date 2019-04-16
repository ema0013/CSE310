import dpkt


class Packet:
    '''
        self-made packet class because I didn't understand how to use the dpkt library
    '''
    def __init__(self, buf, ts):
        self.size = len(buf)
        self.Ethernet = buf[0:14]
        self.IP = buf[14:34]
        self.TCP = buf[34:self.size]
        # parse IP
        self.ttl = self.IP[8]
        self.protocol = self.IP[9]
        self.sourceIP = self.IP[12:16]
        self.destIP = self.IP[16:20]
        self.ts = ts

        self.sourcePort = self.TCP[0:2]
        self.destPort = self.TCP[2:4]
        self.seq = self.TCP[4:8]
        self.ack = self.TCP[8:12]
        self.flags = self.TCP[12:14]
        self.window = self.TCP[14:16]
        self.checksum = self.TCP[16:18]
        # rest of TCP is payload

    def seq_ack(self):
        return self.seq, self.ack


class FlowHalf:
    '''
        This class isn't actually a flow, but rather a 'flow-half'. I store the flow as a tuple
        with format (sender, receiver) with the packets split by the srcport and destport
        starting ack is used for the relative acks
    '''
    def __init__(self, pkt: 'Packet'):
        self.sourcePort = pkt.sourcePort
        self.destPort = pkt.destPort
        self.pkts = [pkt]
        self.starting_ack = pkt.ack

    def part_of_flow(self, pkt: 'Packet'):
        return pkt.destPort == self.destPort and pkt.sourcePort == self.sourcePort

    def add_packet(self, pkt: 'Packet'):
        self.pkts.append(pkt)
        if self.starting_ack == b'\x00\x00\x00\x00':
            self.starting_ack = pkt.ack

    def print_src_dest(self):
        print(int.from_bytes(self.sourcePort, 'big', signed=False), '->',
              int.from_bytes(self.destPort, 'big', signed=False))

    def print_seq_ack_win(self, pkt: 'Packet'):
        if pkt in self.pkts:
            initial = self.pkts[0].seq_ack()
            print('SEQ (relative):' +
                  str(int.from_bytes(pkt.seq_ack()[0], 'big', signed=False)
                      - int.from_bytes(initial[0], 'big', signed=False)) +
                  ' ACK (relative):' +
                  str(int.from_bytes(pkt.seq_ack()[1], 'big', signed=False)
                      - int.from_bytes(self.starting_ack, 'big', signed=False) + 1) +
                  ' Recv Win Size:' +
                  str(pow(2, int.from_bytes(self.pkts[0].TCP[39:40], 'big', signed=False)) *
                      int.from_bytes(pkt.window, 'big', signed=False)))


def main():
    file = open('assignment3.pcap', 'rb')
    pcap = dpkt.pcap.Reader(file)
    # For each packet in the pcap process the contents
    flows_halves = list()
    packets = list()
    # here the packets are separated by having the same srcport and destport
    for timestamp, buf in pcap:
        packet = Packet(buf, timestamp)
        if len(flows_halves) == 0:
            flow = FlowHalf(packet)
            flows_halves.append(flow)
        else:
            count = 0
            for flowHalf in flows_halves:
                if flowHalf.part_of_flow(packet):
                    flowHalf.add_packet(packet)
                    break
                count += 1
            if count == len(flows_halves):
                new_flow_half = FlowHalf(packet)
                flows_halves.append(new_flow_half)
    # join the flow halves together as a tuple
    flows = list()
    for flows_half in flows_halves:
        for flow_half in flows_halves:
            if int.from_bytes(flows_half.destPort, 'big', signed=False) == 80 and flows_half.sourcePort == flow_half.destPort:
                flows.append((flows_half, flow_half))
                break
                # [0] is sender [1] is receiver
    # 1, 2a,b,c
    print('PCAP flows:\n')
    for (sender, receiver) in flows:
        sender.print_src_dest()
        print('Transaction Info:')
        print('Source to Dest: ')
        sender.print_seq_ack_win(sender.pkts[2])
        print('Dest to Source: ')
        receiver.print_seq_ack_win(receiver.pkts[1])
        print('Source to Dest: ')
        sender.print_seq_ack_win(sender.pkts[3])
        print('Dest to Source: ')
        receiver.print_seq_ack_win(receiver.pkts[2])
        # for throughput we look at the receiver side and the acks
        # by subtracting the acks from one another we get how many packets/bytes were sent
        print('Throughput and Packet Loss:')
        pack = receiver.pkts[len(receiver.pkts) - 2]
        time = pack.ts - sender.pkts[2].ts
        sent_packets = int.from_bytes(pack.ack, 'big', signed=False) - \
                        int.from_bytes(receiver.starting_ack, 'big', signed=False)
        # calculate how many lost based on how many dupes/len(packets)
        # len(packets) not same number as sent_packets
        lost = 0
        seqs = list()
        for pkt in sender.pkts:
            if pkt.seq in seqs:
                lost += 1
            else:
                seqs.append(pkt.seq)
        print(str(sent_packets/time), 'bytes-per-second, Packet Loss :', str(lost/len(sender.pkts)*100) + '%\n')
    # part 2.1
    for (sender, receiver) in flows:
        print('Congestion Windows:')
        sender.print_src_dest()
        # rtt is from time sender sends first pack to receives first ack
        # calculate number of packets sent btw this timeframe
        packets_to_add = 0
        packets = 0
        icwnd = 0
        for pkt in sender.pkts:
            if sender.pkts[2].ts <= pkt.ts <= receiver.pkts[1].ts:
                packets += 1
                packets_to_add += 1
                icwnd += pkt.size
        print('icwnd =', packets, 'packets,', icwnd, 'bytes, payload and header')
        # repeat process 4 more times
        for z in range(4):
            packets = 0
            x = 2 + packets_to_add
            y = 1 + packets_to_add
            for pkt in sender.pkts:
                if sender.pkts[x].ts <= pkt.ts <= receiver.pkts[y].ts:
                    packets += 1
                    packets_to_add += 1
                    icwnd += pkt.size
            print('cwnd'+str(z+2)+' =', packets, 'packets,', icwnd, 'bytes, including payload and header')
    # Part 2.2
    print('\n Retransmissions Types:')
    for (sender, receiver) in flows:
        # find triple ack first
        sender.print_src_dest()
        triple = 0
        trip_count = 0
        prev_ack = receiver.pkts[0].ack
        for pkt in receiver.pkts:
            if pkt == receiver.pkts[0]:
                continue
            elif pkt.ack == prev_ack:
                triple += 1
                if triple == 3:
                    trip_count += 1
                    triple = 0
            else:
                triple = 0
            prev_ack = pkt.ack
        print('Retransmission via Triple-Ack:', trip_count)
        # calculating timeouts
        rtt = receiver.pkts[1].ts - sender.pkts[2].ts
        # estimated rtt
        timeouts = 0
        seqs = list()
        for pkt in sender.pkts:
            if pkt.seq in seqs: # retransmission
                time1 = pkt.ts
                prev_pkt = pkt
                for pktt in sender.pkts:
                    if prev_pkt.seq == pktt.seq:
                        prev_pkt = pktt
                        break
                time2 = prev_pkt.ts
                # determine if the retransmission was too late, therefore timeout
                if time1 - time2 > rtt * 2:
                    timeouts += 1
            else:
                seqs.append(pkt.seq)
        print('Retransmission via Timeout:', timeouts, '\n')


if __name__ == '__main__':
    main()
