import socket
import struct


email_to_name = {
    'luke@gmail.com': 'Luke Skywalker',
    'brandon57@yahoo.com': 'Brandon Shwartz',
    'teqotonox-5724@yopmail.com': 'Giacomo Higgins',
    'wortmanj@aol.com': 'Elly Mcghee',
    'scarlet46@gmail.com': 'Ezra Mckeown',
    'cgreuter@att.net': 'Fathima Campbell',
    'grdschl@live.com': 'Stephan Colon',
    'CSummers@aol.com': 'Casey Summers',
    'MMontes@stonybrook.edu': 'Melisa Montes',
    'bhensley1111@bths.edu': 'Brian Hensley',
    'Braunsky669@gmail.com': 'Rhodri Braun',
    'Lfield@harvard.edu': 'Luca Field',
    'Masanathis@yahoo.com': 'Sana Mathis'
}


def create_fmt(size):
    fmt = 'BB' + str(size) + 's'
    return fmt


def get_name(email):
    if email in email_to_name:
        return email_to_name[email]
    else:
        return None


def main():
    host = '127.0.0.1'
    #ip for localhost
    port = 5000
    #arbitrary port

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    while True:
        print("Waiting for connection...")
        connection, addr = s.accept()
        try:
            print("Connection from: "+str(addr))
            while True:
                package = connection.recv(256)
                # 257 since the max size of package is 257 bytes
                if not package:
                    break
                if package[0] != 81:
                    # message is not type Q
                    print("Wrong message type")
                    break
                unpacked = struct.unpack(create_fmt(package[1]), package)
                # package[1] corresponds to message length
                print("From connected user: ", unpacked)
                name_return = get_name(unpacked[2].decode('utf-8'))
                if name_return is None:
                    name_return = 'email not found in database'
                return_pack = struct.pack(create_fmt(len(name_return)), ord('R'), len(name_return), bytes(name_return, 'utf-8'))
                print("Sending: ", struct.unpack(create_fmt(len(name_return)), return_pack))
                connection.send(return_pack)
        finally:
            connection.close()


if __name__ == '__main__':
    main()
