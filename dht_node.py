import os
import sys
import socket
import posix
import hashlib
import copy

k = 160 #max number of nodes
max_entries = 160
port = 10560
DEFAULT_PORT_Min =10560
DEFAULT_PORT_Max =10579
total_hops = 1
last_id = None

"""
HASH METHODS
"""
def getHash( IP, node_port):
    net_ip = socket.gethostbyname(IP)
    net_port = int(node_port)
    try:
        network_byte = socket.inet_aton(net_ip) #gets network byte order
    except ValueError:
        sys.stderr.write(' There was a problem connecting to : %s ' % IP)
    try:
        port_byte = net_port.to_bytes(2,byteorder='big') #gets port byte
    except ValueError:
        sys.stderr.write(' There was a problem connecting to Port: %s ' % str(net_port))
    hash_node_id = hashlib.sha1(network_byte + port_byte).hexdigest()
    hash_id = int(hash_node_id, 16)
    return hash_id
# ip = getHash('cs1.seattleu.edu', '12034')
def getKeyHash(key):
    key_hash= key.encode('UTF-8')
    hashed =  hashlib.sha1(key_hash).hexdigest()
    hash_key = int(hashed,16)
    return hash_key
"""
MISC..
"""
def get_IP(ip_input,port_input):
    ip_add = socket.gethostbyname(ip_input)
    host = socket.getaddrinfo(ip_add,port_input, socket.AF_INET, socket.SOCK_DGRAM)
    out_IP = (host[0][4][0])
    return out_IP

#MINI-CLASS to store info stipped from files
class info_holder:
    id = None
    ip = None
    port = None

    def set_vars(self,id,ip,port):
        self.id = id
        self.ip = ip
        self.port = port
    def clear(self):
        self.id = None
        self.ip = None
        self.port = None
"""
FINGER TABLE CLASS
"""
class Finger_Table:
    fingers = None
    def __init__(self, arr):
        self.fingers = []
        print('size is ' + str(len(arr)))
        for i in range (len(arr)):
            node = neighbor_node()
            self.id = arr[i].id
            self.ip = arr[i].ip
            self.port = arr[i].port
            node.set(self.id, self.ip, self.port)
            self.fingers.insert(i, node)
            node.print()
            node.clear()

    def print_nodes(self):
        print('Finger_LIST PRINTOUT:')
        for i in range(len(self.fingers)):
            temp = self.fingers[i]
            print(str(temp.id) + ' IP' + (str(temp.ip)))

"""
NEIGHBOR Class (SUCCESSORS/ PREDECESSORS)
"""
class neighbor_node:
    def __init__(self):
        self.id =None
        self.ip = None
        self.port =None
        self.finger = None
    # replace via passed array
    def set_node(self,arr):
        self.id = arr[0]
        self.ip = arr[1]
        self.port = arr[2]
    #ppss in arguments to set info
    def set(self, id, ip, port):
        self.id = id
        self.ip = ip
        self.port = port
    #appends finger table to successor
    def add_finger(self,ft):
        self.finger = ft
    #organize fingers list O(N) need log(n)
    def sort_fingers(self):
        #organize finger to hold elements after a finger
        temp_arr = []
        temp_arr2 = []
        for i, iter_node  in enumerate(self.finger.fingers,0):
            if(iter_node.id <= self.id and  iter_node.port != self.port ):
                temp_arr2.append(iter_node)
            elif(iter_node.id > self.id and  iter_node.port != self.port ):
                temp_arr.append(iter_node)
            else:
                continue
            print(str(iter_node.id) + ' has been added to finger list')
        combined = temp_arr + temp_arr2
        self.finger.fingers = combined
    #various print functions
    def print_fingers(self):
        for i, iter_node in enumerate(self.finger.fingers, 0):
            print(str(self.finger.fingers[i].id )+ ' is ordered #'+ str(i))
    def print(self):
        print('Node{ID: '+ str(self.id) + ' IP:'+ str(self.ip) + 'Port: '+ str(self.port) + '}')
    def clear(self):
        id= None
        ip = None
        port = None
        finger = None
"""
NODES CLASS
"""
class Node:
    id= None
    ip = ''
    port = ''
    key = None
    next = None
    predecessor= None
    data = None
    storage_size = 160
    finger = None

    def __init__(self, ID,IP, Port, Pred ,ft):
        self.data = {}
        self.id = ID
        self.ip = IP
        self.port = Port
        self.predecessor = Pred
        self.finger = Finger_Table(ft)
        self.print_fingers()
    def add_finger(self, dt):
        self.finger.append(dt)
    def print_fingers(self):
        for i, iter_node in enumerate(self.finger.fingers, 0):
            print(str(self.finger.fingers[i].id )+ ' is ordered #'+ str(i))

    def find_distance(self, id, key):
        # case node is far from key
        # print("finding dist:\n id: " + str(id) + ' \n vs  key ' + str(key))
        x= int(id)
        y= int(key)
        if x > y: #if id les than y return low value
            return (2 ** k) - (y-x)
        # case node is less than key
        elif x < y: #if id greater than y return high value
            return y-x
        # case distance is approximately the same as key
        elif(x == y): #best option
            return 0
        else:
            return 0
    def find_node(self , i_key):
        global total_hops
        total_hops = +1  #should account for next and followng finger node
        key = int(i_key)
        current_node = copy.copy(self)
        #should be first second on list
        ret_node = info_holder()
        ret_node.set_vars(current_node.finger.fingers[0].id , current_node.finger.fingers[0].ip,
                          current_node.finger.fingers[0].port)
        i = 1
        d1 = self.find_distance(ret_node.id, key) #distance of current
        d2 = self.find_distance(current_node.finger.fingers[i].id, key) #distance of successor
        if (key > ret_node.id > current_node.finger.fingers[i].id):  # key > last node, next node is first node
            # total_hops +=1
            ret_node.set_vars(current_node.finger.fingers[i].id, current_node.finger.fingers[i].ip,
                                 current_node.finger.fingers[i].port)
            return ret_node
        if(d1 < d2 ):
            return ret_node
        else:

            while(d1 >  d2 ): # need first case where d2 is greater than d1
                total_hops +=1
                ret_node.set_vars(current_node.finger.fingers[i].id,
                                 current_node.finger.fingers[i].ip,
                                 current_node.finger.fingers[i].port)
                d1 = self.find_distance(ret_node.id, key)
                i = i + 1
                if(i == len(self.finger.fingers)):
                    ret_node.set_vars(previous_node.id,
                                      previous_node.ip,
                                      previous_node.port)
                    return ret_node
                d2 = self.find_distance(current_node.finger.fingers[i].id, key)
                # if(d2 <  best_dist):
                #     optimal_node.set_vars(current_node.finger.fingers[i].id,
                #                       current_node.finger.fingers[i].ip,
                #                       current_node.finger.fingers[i].port)

                if (d1 > d2):
                    print('d1:' + str(d1) + ' is greater than  d2: ' + str(d2))

                else:
                    print('d1:' + str(d1) + ' is less than  d2: ' + str(d2))
                    ret_node.set_vars(current_node.finger.fingers[i].id,
                                      current_node.finger.fingers[i].ip,
                                      current_node.finger.fingers[i].port)
                    return ret_node
                if (key > ret_node.id > current_node.finger.fingers[i].id):  # key > last node, next node is first node
                    ret_node.set_vars(current_node.finger.fingers[i].id, current_node.finger.fingers[i].ip, current_node.finger.fingers[i].port)
                    return ret_node
                # print('PREVIOUS d1:' + str(d1) + ' d2: ' + str(d2))

        print('Total hops: '+ str(total_hops))#test
        return ret_node
    def lookup(self, hash_key):
        print(self.data)
        global total_hops
        key = int(getKeyHash(hash_key))
        current_node = (self)
        c_id = current_node.id
        pred_id = current_node.predecessor.id
        next_id = self.finger.fingers[0].id
        next_ip = self.finger.fingers[0].ip
        next_port = self.finger.fingers[0].port
        target_node = info_holder()
        target_node.set_vars(next_id, next_ip, next_port)
        h_key = key % max_entries
        # print('Lookup KEY : '+ str(key) + ' cid: ' + str(c_id) + 'next id :'+ str(next_id) + 'pred: '+ str(pred_id))
        if (h_key in self.data):
            return current_node
        if(pred_id < key <= c_id):
            if(h_key not in self.data):
                return None
            else:
                return current_node
        elif(key < c_id < pred_id): #pred_id is last element-
            if (self.storage_size != 0):
                if (h_key not in self.data):
                    return None
                else:
                    return current_node
            else:
                return target_node
        elif (key > c_id > next_id): #cid is last elment
            total_hops += 1
            return target_node
        elif (key < pred_id and key > c_id):
            target_node.set_vars(self.predecessor.id, self.predecessor.ip, self.predecessor.port)
            total_hops += 1
            return target_node
        else: #FINE NEXT KEY THAT HAS ELEMENT
            nxt_node = current_node.find_node(key)
            return nxt_node
        return target_node

    def lookup_store(self, hash_key , entry):
        global total_hops
        key = int(getKeyHash(hash_key))
        current_node = self
        c_id = current_node.id
        pred_id = current_node.predecessor.id
        next_id = self.finger.fingers[0].id
        next_ip = self.finger.fingers[0].ip
        next_port = self.finger.fingers[0].port
        target_node = info_holder()
        target_node.set_vars(next_id, next_ip, next_port)
        store_key = key % max_entries
        if (key in self.data):
            if(self.storage_size !=0):
                if(entry_val == 'del'):
                    del self.data[store_key]
                    return current_node
                else:
                    self.data[store_key] = entry
                    # self.storage_size -= 1
                    sys.stderr.write('KEY: '+hash_key + ' replaced with Value:'+ str(entry))
                    return current_node
            else:
                return target_node
        elif (pred_id < key <= c_id):  # KEY IS WITHIN KEY RANGE
            if (self.storage_size != 0):
                if(store_key in self.data):
                    if(entry_val == 'del'):
                        del self.data[store_key]
                        return current_node
                else:
                    self.data[store_key] = entry  # replace data
                    print(self.data)
                    print('New Entry:'+ str(entry)+ ' for  key: '+ str(key) )
                    return current_node
            else:
                return target_node
        elif(key < c_id < pred_id): #predecessor should be las tnode
            if (self.storage_size != 0):
                if (entry_val == 'del'):
                    del self.data[store_key]
                    return current_node
                else:
                    self.data[store_key] = entry  # replace data
                    print(self.data)
                    print('New Entry:' + str(entry) + ' for  key: ' + str(key))
                    return current_node
            else:
                return target_node
        elif (key > c_id > next_id): #is last what not sore in next
            total_hops += 1
            return target_node
        elif(key > pred_id > c_id): #predecessor last in list, you are first elment
            if (self.storage_size != 0):
                if (entry_val == 'del'):
                    del self.data[store_key]
                    return current_node
                else:
                    self.data[store_key] = entry
                    return current_node
            else:
                return target_node
        elif(key < pred_id and key >c_id):
            target_node.set_vars(self.predecessor.id, self.predecessor.ip, self.predecessor.port)
            total_hops +=1
            return target_node
        else:  # FINE NEXT KEY THAT HAS ELEMENT
            nxt_node = current_node.find_node(key)
            if (nxt_node is None):
                nxt_node == target_node
            return nxt_node
        print('Total hops '+ str(total_hops))
        return target_node


"""
    NODE SETUP
"""
#check args
if(len(sys.argv) != 3):
    print('Invalid Number of Arguements: Enter a valid filename and/or key', file=sys.stderr)
    sys.exit(1)
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error as e:
    sys.stderr.write('Failed to create socket. Error: ' + str(e[0]))
    sys.exit(1)
file_name= sys.argv[1]
line_num = int(sys.argv[2]) #line searched in file
#main node
node_info= None
node_info= None
node_IP= None
node_hash_id= None
node_port= None
#SUCCESSOR AND PREDECESSOR MAY FIX
next_node = neighbor_node() #hold current node's next id,ip,port
previous_node =neighbor_node()
file_arr= []
sum = 0
main_node = None
with open(file_name,'r') as file_nodes: #strip file
    for num, line in enumerate(file_nodes, 0):
        node_info = line.split()
        finger_ip = node_info[0]
        finger_port = node_info[1]
        try:
            ipv = get_IP(finger_ip, finger_port)
        except ValueError:
            sys.stderr.write(' There was a problem getting IP: %s ' % finger_ip)
        finger_hash_id = getHash(ipv, finger_port)
        node_tuple = [num, finger_hash_id, ipv ,finger_port]
        print(str(node_tuple))
        file_arr.insert(num, node_tuple)
        print('line added')
        if (num == line_num):
            print('Match')
            node_IP = node_info[0]
            node_port = node_info[1]
            ipv = get_IP(node_IP, node_port)
            node_hash_id = getHash(ipv, node_port)
            main_node = node_tuple
        sum += 1
file_nodes.close()
file_arr.sort(key=lambda ID: ID[1], reverse= False) #sort list
print('MAIN NODE ')
print(main_node)
main_pos = file_arr.index(main_node)
prev_pos = file_arr[main_pos - 1]
previous_node.set_node([prev_pos[1],prev_pos[2],prev_pos[3]])
last_id = file_arr[-1][1] # ID of last element in sort
file_arr_size = len(file_arr[0])
k = sum-1 #set k to match
finger_count = 1 #first finger get neightbor ahead stored
fingers_arr = []
while (finger_count < file_arr_size)/2:
    current_node_pos = main_pos + finger_count
    if(current_node_pos > file_arr_size):
        #start at lower node
        current_node_pos -= file_arr_size
    fi_id = file_arr[current_node_pos][1]
    fi_ip = file_arr[current_node_pos][2]
    fi_port = file_arr[current_node_pos][3]
    new_fing = info_holder()
    new_fing.set_vars(fi_id, fi_ip, fi_port)
    fingers_arr.append(new_fing)
    finger_count *= 2 #increase in power

Current_node = Node(node_hash_id, node_IP, node_port, previous_node,fingers_arr)
print('-------------NODE INFORMATION-----------------')
print(' MAIN Node ID:\n' + str(Current_node.id) + ' IP: ' + str(Current_node.ip) + ' port: ' + str(Current_node.port) + '\n ------------------\n')
print ('PRECESSOR NODE ID: \n'+str(previous_node.id))
"""
IPS/PORT/HOSTNAMES
"""
try:
    node_host = socket.gethostbyname(node_IP)  # should be name of server
except socket.error as e:
    sys.stderr.write(('Failed to get host name. Error: ' + str(e[0])))
    sys.exit(1)

print ('Starting up on Node_ID: ' + str(node_hash_id) + ' IP: ' + node_host + ' Port: ' + str(node_port))
"""
Binding
"""
sock.bind((node_host,int(node_port)))

#LISTEN FOR MESSAGES
while True:
    print('\n Waiting for message on ' + str(Current_node.id))
    print('port:' + Current_node.port)
    total_hops = 0
    data, addr = sock.recvfrom(1024)
    # print(data)
    data_decode= data.decode('UTF-8')
    print('MESSAGE RECEIVED')
    print('----------------')
    print(data_decode)
    data_decode=data_decode.replace('\r\n', ':')
    request= data_decode.split(':')

    print('request info:' + str(request))
    """
    FOR FORWARDED MESSAGES
    """
    if(request[0] == 'FRWD'):
        target_node_ip = request[1].strip()
        target_port = int(request[2].strip())
        hash_id = getHash(target_node_ip,target_port)
        client_addr = str(request[4]).strip()
        client_port = int(request[6])  # client port
        req_type = request[8]  # get or put
        total_hops = int(request[10])
        key = request[12]

        """
        DEAL WITH NORMAL FORWARDING
        """
        if(int(hash_id) == int(Current_node.id) and int(target_port) == int(Current_node.port)):
            if(req_type =='put'):
                print('HANDLING PUT MESSAGE')
                entry_val = request[14].strip()
                get_val = Current_node.lookup_store(key, entry_val)
                if(get_val.ip == Current_node.ip):
                    if(entry_val != 'del'):
                        message = 'ACK: NODE_ID: '+ str(Current_node.id)+' has stored Value:' + str(entry_val) + ' Inserted  Key:' + str(int(getKeyHash(key)) % max_entries)
                        message += ' Total Hops:' + str(total_hops) + '\r\n'
                        message = message.encode('UTF-8')
                        sock.sendto(message, (client_addr, client_port))  # send to client
                        print('INSERTED VALUE')
                    else:
                        message = 'ACK: NODE_ID:' + str(Current_node.id) +' has Deleted potential Value on Key:' + str(int(getKeyHash(key)) % max_entries)
                        message += ' Total Hops:' + str(total_hops) + '\r\n'
                        message = message.encode('UTF-8')
                        sock.sendto(message, (client_addr, client_port))  # send to client
                else:
                    message = 'FRWD: ' + str(get_val.ip) + ':' + str(get_val.port) + '\r\n'
                    message += 'Client Info: ' + str(client_addr) + '\r\n'
                    message += 'Port: ' + str(client_port) + '\r\n'
                    message += 'Type:' + req_type + '\r\n'
                    message += 'Hops:' + str(total_hops) + '\r\n'
                    message += 'Key:' + str(key) + '\r\n'
                    if (req_type == 'put'):
                        entry_val = request[14]
                        message += 'Entry:' + entry_val
                    if (Current_node.storage_size == 0):
                        message += 'SIZE: Full\r\n\r\n'
                    message = message.encode('UTF-8')
                    out_ip = get_val.ip
                    out_port = int(get_val.port)
                    Extract_IP = get_IP(out_ip, out_port)
                    sock.sendto(message, (Extract_IP, out_port))
                    print('FORWARDING  PUT MESSAGE TO ID: ' + str(get_val.id) + ': ' + str(out_port))

            elif(req_type=='get'):
                print('HANDLING GET MESSAGE')
                get_val = Current_node.lookup(key)
                if(get_val == None ):
                    message = 'ACK: ENTRY DOES NOT EXIST'
                    message = message.encode('UTF-8')
                    sock.sendto(message, (client_addr, client_port))
                elif(get_val.id == Current_node.id):
                    hash_k = int(getKeyHash(key)) % max_entries
                    if hash_k not in Current_node.data:
                        print('ping')
                        message = 'ERROR: No Value for Key:' + str(key)
                        message = message.encode('UTF-8')
                        sock.sendto(message, (client_addr, client_port))  # send to client
                        print('RETURNED VALUE' )
                    else:
                        print('pint')
                        ret_val = Current_node.data[hash_k]
                        message = 'ACK: NODE_ID: '+ str(Current_node.id)+' has has Value:' + str(ret_val) + ' From Key:' + str(key)
                        message = message.encode('UTF-8')
                        sock.sendto(message, (client_addr, client_port))  # send to client
                        print('RETURNED VALUE')
                elif(get_val.id != Current_node.id):
                    message = 'FRWD: ' + str(get_val.ip) + ':' + str(get_val.port) + '\r\n'
                    message += 'Client Info: ' + str(client_addr) + '\r\n'
                    message += 'Port: ' + str(client_port) + '\r\n'
                    message += 'Type:' + req_type + '\r\n'
                    message += 'Hops:' + str(total_hops) + '\r\n'
                    message += 'Key:' + str(key) + '\r\n'
                    if (Current_node.storage_size == 0):
                        message += 'SIZE: Full\r\n\r\n'
                    message = message.encode('UTF-8')
                    out_ip = get_val.ip
                    out_port = int(get_val.port)
                    Extract_IP = get_IP(out_ip, out_port)
                    sock.sendto(message, (Extract_IP, out_port))
                    print('FORWARDING GET MESSAGE TO NODE_ID: ' + str(get_val.id) + ': ' + str(out_port))
        else:
            hash_k = int(getKeyHash(key)) % max_entries
            print('THIS HIT')
            if hash_k not in Current_node.data:
                message = 'ERROR: No Value for Key:' + str(key)
                message = message.encode('UTF-8')
                sock.sendto(message, (client_addr, client_port))  # send to client
                print('RETURNED VALUE' + str(client_port))
            else:
                total_hops +=1
                message = 'FRWD: ' + str(target_node_ip) + ':' + str(target_port) + '\r\n'
                message += 'Client Info: ' + str(client_addr) + '\r\n'
                message += 'Port: ' + str(client_port) + '\r\n'
                message += 'Type:' + req_type + '\r\n'
                message += 'Hops:' + str(total_hops) + '\r\n'
                message += 'Key:' + str(key) + '\r\n'
                if (req_type == 'put'):
                    entry_val = request[14]
                    message += 'Entry:' + entry_val
                if (Current_node.storage_size == 0):
                    message += 'SIZE: Full\r\n\r\n'
                message = message.encode('UTF-8')
                out_ip = Current_node.next.ip
                out_port = int(Current_node.next.port)
                Extract_IP = get_IP(out_ip,out_port)
                sock.sendto(message, (Extract_IP, out_port))
                print('MESSAGE SENT TO NODE_ID: ' + str(get_val.id)+': '+ str(out_port))

    elif(request[0] == 'Init'):
        """
          HANDLES FIRST REQUESTS FROM CLIENT
        """
        req_type= request[3].strip()
        key = request[5].strip()
        client_addr = addr[0]
        client_port=  addr[1]
        print(client_addr)
        #catch
        key_hash = int(getKeyHash(key)) % max_entries
        """
        GET/PUT REQUESTS
        """
        if(req_type == 'get'):
            print('HANDLING GET MESSAGE')
            get_val = Current_node.lookup(key)
            if (get_val == None):
                message = 'ACK: ENTRY DOES NOT EXIST'
                message = message.encode('UTF-8')
                sock.sendto(message, (client_addr, client_port))
            elif(get_val.id == Current_node.id ):
                if key_hash not in Current_node.data:
                    message = 'ERROR: No Value for Key:' + str(key)
                    message = message.encode('UTF-8')
                    sock.sendto(message, (client_addr, client_port))  # send to client
                    print('RETURNED VALUE')
                else:
                    ret_val = Current_node.data[key_hash]
                    message = 'ACK: NODE_ID: '+ str(Current_node.id)+' has Value:' + str(ret_val) + ' with Key:' + str(key)
                    message = message.encode('UTF-8')
                    sock.sendto(message, (client_addr, client_port))  # send to client
                    print('RETURNED VALUE')
            elif(get_val.id != Current_node.id):
                if(total_hops != 1):
                    next_target_node = get_val.ip # node ip of next send
                    next_target_port = int(get_val.port) #port for next send
                    next_target_IP = get_IP(next_target_node, next_target_port)
                    print(str(get_val.id))
                    message ='FRWD: '+ str(next_target_IP) + ':'+ str(next_target_port) +'\r\n'
                    message += 'Client Info: ' + str(client_addr) +  '\r\n'
                    message += 'Port: ' + str(client_port) + '\r\n'
                    message +='Type:'+ req_type +'\r\n'
                    message +='Hops:' +str(total_hops)+ '\r\n'
                    message +='Key:'+ str(key) + '\r\n'
                    message +='Client IP: ' + str(client_addr) +'\r\n'
                    message += 'Port: ' + str(client_port)  +'\r\n'
                    if(Current_node.storage_size == 0):
                        message +='SIZE: Full\r\n\r\n'
                    message = message.encode('UTF-8')
                    sock.sendto(message, (next_target_IP, next_target_port))
                    print('MESSAGE SENT TO NODE ID: '+ str(get_val.id) + ' IP: '+str(next_target_IP)+': '+ str(next_target_port))
            else:
                print('Should not fit')
        elif(req_type == 'put'):
            entry_val = request[7]
            if(entry_val == ''): #redundacy, handled in client
                message = 'ERROR:' + 'Value was blank, no insert'
                sock.sendto(message, (client_addr, client_port))
            else:#get hash
             get_val = Current_node.lookup_store(key, entry_val)
             if (Current_node.id != get_val.id):
                 print('FORWARDING MESSAGE TO NODE: ' + str(get_val.id))
                 next_target_node = get_val.ip  # node ip of next send
                 next_target_port = int(get_val.port)  # port for next send
                 next_target_IP = get_IP(next_target_node, next_target_port)
                 message = 'FRWD: ' + str(next_target_IP) + ':' + str(next_target_port) + '\r\n'
                 message += 'Client Info: ' + str(client_addr) +'\r\n'
                 message += 'Port: ' + str(client_port) + '\r\n'
                 message +='Type:' + req_type + '\r\n'
                 message +='Hops:' + str(total_hops) + '\r\n'
                 message +='Key:'+ str(key) + '\r\n'
                 message += 'Entry:' + entry_val
                 if (Current_node.storage_size == 0):
                     message += 'SIZE: Full\r\n\r\n'
                 message = message.encode('UTF-8')
                 sock.sendto(message, (next_target_IP, next_target_port))
                 print(message)
                 print('MESSAGE SENT TO NODE ID ' + str(get_val.id) + ' IP: ' + str(next_target_IP) + ': ' + str(
                     next_target_port))

             elif(Current_node.id == get_val.id): #at point
                temp = (getKeyHash(key) % max_entries)
                print('CHECK CURRENT NDOE')
                if(entry_val != 'del'):

                    message = 'ACK: Node_ID: '+ str(Current_node.id) +' has inserted Value:'+ str(entry_val)+ \
                              ' with Key :' + str(temp)
                    message +=' Total Hops:' + str(total_hops) + '\r\n'
                    message = message.encode('UTF-8')
                    sock.sendto(message, (client_addr, client_port))  # send to client
                    print('ENTRY HAS BEEN INSERTED' + str(Current_node.data))
                else:
                    message = 'ACK: NODE_ID: ' + str(Current_node.id) + ' has DELETED Value:' + str(
                        entry_val) + ' ON Key:' + str(temp)
                    message += ' Total Hops:' + str(total_hops) + '\r\n'
                    message = message.encode('UTF-8')
                    sock.sendto(message, (client_addr, client_port))  # send to client
                    print('INSERTED VALUE')
             else:
                 print('unhandled event')
        else:
            print('INVALID REQ TYPE')
            sys.exit(1)
        """
        REQUEST FINISH 
        """
    print('Request Handled')