import calendar
import time
import datetime
import dns.name
import dns.message
import dns.query
import dns.flags
import sys

ROOT_SERVERS = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10',
                '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30',
                '193.0.14.129', '199.7.83.42', '202.12.27.33']


def dns_resolver(domain):
    domain = dns.name.from_text(domain)
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.root)
    query_start = time.time()
    print('Querying for', domain)
    for server in ROOT_SERVERS:
        try:
            print('Trying server', server)
            query = dns.message.make_query(domain, 'A')
            data = dns.query.udp(query, server, 5)
            if len(data.answer) == 0:
                print('No response from server', server)
            else:
                return data, ((time.time() - query_start) * 1000)
            #return a tuple for now
        except dns.exception.Timeout:
            print('Timeout occurred')


if __name__ == '__main__':
    dns_data = dns_resolver(sys.argv[1])
    print(';QUESTION SECTION:')
    for question in dns_data[0].question:
       print(question)
    print(';ANSWER SECTION:')
    for answer in dns_data[0].answer:
        print(answer)
    print('Query Time: ', int(dns_data[1]), 'ms')
    print('WHEN:', datetime.datetime.now().strftime('%a'), datetime.datetime.now().strftime('%h'),
          datetime.datetime.now().strftime('%d'), datetime.datetime.now().strftime('%H:%M:%S'),
          datetime.datetime.now().strftime('%Y'))
    print('Message size rcvd:', len(dns_data[0].to_wire()))




