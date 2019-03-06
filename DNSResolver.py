import dns.query
import dns.resolver

HOST = "www.cnn.com"
answers = dns.resolver.query(HOST, 'A')
#for answer in answers:
#    print(answer)
if answers.rrset is not None:
    print(answers.rrset)







