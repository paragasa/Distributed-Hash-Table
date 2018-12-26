import hashlib
import os
import sys
import socket
import posix


glob_key_size = 32

node_port = 10560
DEFAULT_PORT_Min =10560
DEFAULT_PORT_Max =10578
key = None
req_type=''
entry_val = None

"""
NODE_METHODS
distance from point x to destination y
"""

#check args
if(len(sys.argv) < 5 or len(sys.argv) > 6):
    print('Invalid Number of Arguements', file=sys.stderr)
    sys.exit(1)

if(len(sys.argv) ==  5):
    val = sys.argv[3]
    req_type = val.strip()
elif((len(sys.argv) ==  6)):
    val = sys.argv[3]
    req_type = val.strip()
else:
    print('No implementations', file=sys.stderr)
    sys.exit(1)
if(req_type != 'put' and req_type != 'get'):
    print('Not a valid Request Type, please use get|put', file=sys.stderr)
    sys.exit(1)
# check port
if(sys.argv[2].isdigit()):
    val = sys.argv[2]
    node_port = int(val.strip())
else:
    print('Not a integer for port argument', file=sys.stderr)
    sys.exit(1)

#TODO CHANGE DEFAULT PORTS
if(int(DEFAULT_PORT_Max) < DEFAULT_PORT_Min or DEFAULT_PORT_Max > DEFAULT_PORT_Max ):
    print('Port Number is Invalid', file=sys.stderr)
    sys.exit(1)
#KEYS
try:
    key_input= sys.argv[4].strip()
except:
    print('Error in key entry')
    sys.exit(1)
if(len(key_input)> 255):
    print('Key Input too long must be  1- 255 characters. \n Try again. User Input:' + key_input)
    sys.exit(1)
if(req_type == 'put'):
    if(len(sys.argv)== 5):
        entry_val = 'del'
    else:
        entry_val = sys.argv[5].strip()
        if (len(entry_val) > 255):
            print('Entry Input too long must be  1- 255 characters. \n Try again. User Input:' + entry_val)
            sys.exit(1)
        if(entry_val == 'del'):
            print('USED PHRASE IN DELETION. \n Try again. User Input:' + entry_val)
            sys.exit(1)

"""
SETUP SOCKET AND HOST
"""
#SETUP HOST AND PORTS
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error as e:
    print('Failed to create socket. Error: ' + str(e[0]), file=sys.stderr)
    sys.exit(1)

try:
    cli_addr = socket.gethostbyname('')
    host = socket.getaddrinfo(cli_addr,node_port,socket.AF_INET, socket.SOCK_DGRAM)
except os.error as e:
    print('Error: '+ str(e[0]) +'Could not find IP Address:',file=sys.stderr)
    sys.exit(1)
IP = (host[0][4][0])
try:
    s.bind((IP,DEFAULT_PORT_Max))#CHANGE
except socket.error as e:
    print('Bind failed. Error: ' + str(e), file=sys.stderr)
    sys.exit(1)

"""
MAIN
"""
message= 'Init: \r\n'
message += ('Type:' + req_type + '\r\n ')
message += ('Key:' + key_input + '\r\n ')

if(req_type == 'put'):
    message += 'Entry:' + entry_val
#SEND
message = message.encode('UTF-8')
s.sendto(message, (IP,node_port))
#RECEIVE
data, addr = s.recvfrom(1024)
ret = data.decode('UTF-8')
decoded_data= ret.split(':')
print('Response Retrived:')
if(decoded_data[0]== 'ACK'):
    print(ret)
elif(decoded_data[0]=='ERROR'):
    print(ret)
else:
    print('UNKNOWN RESPONSE')