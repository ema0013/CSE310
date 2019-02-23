import socket
import struct


def create_fmt(size):
    fmt = 'BB' + str(size) + 's'
    return fmt


def main():
    host = '127.0.0.1'
    port = 5000

    s = socket.socket()
    s.connect((host, port))
    print('Connected to Server')

    message = input("Enter message type->")
    while message != 'quit':
        m_type = ord(message[0])
        # message type stored as 1 byte char
        message = input("Enter message size->")
        m_size = int(message)
        # store length as 1 byte char???
        if m_size > 254:
            print('Message size cannot be longer than 254')
            message = input('Enter message type->')
            continue
        message = input("Enter message->")
        m_data = bytes(message, 'utf-8')
        # create fmt string
        fmt = create_fmt(m_size)
        package = struct.pack(fmt, m_type, m_size, m_data)

        print('Sending:', struct.unpack(fmt, package))
        s.send(package)
        received_pack = s.recv(256)
        # 257 since the max size of package is 257 bytes
        unpacked = struct.unpack(create_fmt(received_pack[1]), received_pack)
        print('Received from server: ', unpacked)
        message = input("Enter message type->")
    s.close()


if __name__ == '__main__':
    main()

