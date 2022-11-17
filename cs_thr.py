import socket,os,sys,threading,sctp,time,subprocess

pkt = ''

def main():


    pid = os.fork()

    if(pid > 0):
        client()
    else:
        
        server()

def client():
    def convertFileIntoList(file):
        read = file.read()
        ret = read.split(' ')
        return ret

    SERVER = []
    if (len(sys.argv)>1):
        SERVER.append(sys.argv[1])
    else:
        time.sleep(0.5)
        while True:
            fileRead = open('ips.txt','r')
            leave = fileRead.read()
            if(len(leave)>0):
                SERVER = leave.split(' ')
                print('entrou')
                fileRead.close()
                break
            fileRead.close()

        print('SERVER =',SERVER)



    PORT = 8000
    while True:
        for x in SERVER:
            try:
                client = sctp.sctpsocket_tcp(socket.AF_INET)
                client.connect((x, PORT))
                print('servers:',SERVER)
                while True:

                    print('servers:',SERVER)
                    out_data = input()
                    if out_data=='bye' or out_data=='sniff':
                        client.sendall(bytes(out_data,'UTF-8'))
                        break
                    else:
                        client.sendall(bytes(' '.join(SERVER),'utf-8'))
                client.close()
            except:
                print('error while connecting, removing ip from list')
                SERVER.remove(x)
        fR = open('ips.txt','r')
        SERVER = convertFileIntoList(fR)
        fR.close()

def server():
    try:
        createFile = open('ips.txt','x')
        createFile.close()
    except:
        print('file already created')
    pkt = startCapturingPkt()
    ips = []
    def checkRepetition(new):
        for x in ips:
            if(x==new):
                return True

        return False

    def writeIpsIntoFile(ips):
        fileWrite = open('ips.txt','w')
        w = ' '.join(ips)
        fileWrite.write(w)
        fileWrite.close()

    class ClientThread(threading.Thread):
        def __init__(self,clientAddress,clientsocket):
            threading.Thread.__init__(self)
            self.csocket = clientsocket
            print ("New connection added: ", clientAddress)
        def run(self):
            print ("Connection from : ", clientAddress)
            if (not checkRepetition(clientAddress[0])):
                ips.append(clientAddress[0])
                writeIpsIntoFile(ips)
            #self.csocket.send(bytes("Hi, This is from Server..",'utf-8'))
            msg = ''
            while True:
                data = self.csocket.recv(2048)
                msg = data.decode('utf-8')
                if msg=='bye' or msg=='':
                    break
                elif msg == 'sniff':
                    stopCapturingPkt(pkt)
                    tcprd = subprocess.run(['tcpdump','-r','cap.pcap'])
                    print(tcprd.stdout.decode())
                    pkt = startCapturingPkt()
                else:
                    tmp = msg.split(' ')
                    for ip in tmp:
                        if not checkRepetition(ip):
                            ips.append(ip)
                    writeIpsIntoFile(ips)
                print ("from client", msg)
            ips.remove(clientAddress[0])
            print ("Client at ", clientAddress , " disconnected...")
    LOCALHOST = ''
    PORT = 8000
    server = sctp.sctpsocket_tcp(socket.AF_INET)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LOCALHOST, PORT))
    print("Server started")
    print("Waiting for client request..")
    while True:
        server.listen(1)
        clientsock, clientAddress = server.accept()
        newthread = ClientThread(clientAddress, clientsock)
        newthread.start()

def stopCapturingPkt(proc):
    proc.kill()

def startCapturingPkt():
    cmd = "tcpdump -w cap.pcap -c 1000 sctp"
    proc = subprocess.Popen(cmd.split(' '))
    return proc 


main()
