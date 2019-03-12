import time
import datetime
import dns.name
import dns.message
import dns.query
import dns.flags
import dns.resolver
import sys

server = '199.7.91.13' #root server of choice


def dns_resolver(domain):
    domain = dns.name.from_text(domain)
    if not domain.is_absolute(): #the domain name has to be absolute
        domain = domain.concatenate(dns.name.root)
    query_start = time.time() #start query time
    try:
        query = dns.message.make_query(domain, dns.rdatatype.from_text('NS')) #query for name server
        data = dns.query.udp(query, server, 200) #timeout is 200 seconds per root server
        #check if answer section empty
        while len(data.answer) == 0:
            name_server = ''
            if len(data.additional) == 0: #if there's nothing in additional
                break
            for additional in data.additional:
                additional_parsed = additional.to_text().split(' ')
                if additional_parsed[3] == 'A': #make sure it's response type 'A'
                    name_server = additional_parsed[4].split('\n')[0]
                    break
            data = dns.query.udp(query, name_server, 200) #query name server for the initial query
        auth_server = ''
        if len(data.additional) == 0 and len(data.answer) == 0: #if only authorities are returned
            for authority in data.authority:
                authority_parsed = authority.to_text().split(' ')
                if authority_parsed[3] == 'NS': #make sure it's response type 'NS'
                    auth_server = authority_parsed[4].split('\n')[0]
                    break
        else:
            auth_server = data.answer[0].to_text().split(' ')[4].split('\n')[0]  # authoritative server
        auth_query = dns.message.make_query(auth_server, dns.rdatatype.from_text('A')) #get the auth server ip
        auth_data = dns.query.udp(auth_query, server, 200)
        while len(auth_data.answer) == 0:
            for additional in auth_data.additional:
                additional_parsed = additional.to_text().split(' ')
                if additional_parsed[3] == 'A': #make sure its response type 'A'
                    name_server = additional_parsed[4].split('\n')[0] # parse out the name server
                    break
            auth_data = dns.query.udp(auth_query, name_server, 200)  # query name server for the initial query
        #get the ip of answer
        auth_server = auth_data.answer[0].to_text().split(' ')[4].split('\n')[0]
        query = dns.message.make_query(domain, dns.rdatatype.from_text('A'))
        data = dns.query.udp(query, auth_server, 200) #this is where we query authority server for the ip of domain
        total_time = ((time.time() - query_start) * 1000) #total time it took to query
        return data, total_time
        #return a tuple for now
    except dns.exception.Timeout:
        print('Timeout occurred')


if __name__ == '__main__':
    dns_data = dns_resolver(sys.argv[0]) #system arg so we can run from cmd
    print(';QUESTION SECTION:')
    for question in dns_data[0].question:
        print(question)
    print(';ANSWER SECTION:')
    for answer in dns_data[0].answer:
        print(answer)
    print('Query Time:', int(dns_data[1]), 'ms')
    print('WHEN:', datetime.datetime.now().strftime('%a'), datetime.datetime.now().strftime('%h'),
        datetime.datetime.now().strftime('%d'), datetime.datetime.now().strftime('%H:%M:%S'),
        datetime.datetime.now().strftime('%Y')) #current time
    print('Message size rcvd:', len(dns_data[0].to_wire())) #towired length of the data




