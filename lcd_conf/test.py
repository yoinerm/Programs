# from monitors import _32BDL4550D_BAT_BEN
from nmap import nmap
from colorama import Fore
import socket, monitors, subprocess, time


def nmapper():
    HOST = nmapper_2()
    a = nmap.PortScanner()
    # a.scan(hosts='192.168.0.1/24', arguments='-PR')
    
    # a.scan(hosts='10.100.0.1/24', arguments='-sn')
    a.scan(hosts=f'{HOST}/24', arguments='-sn')
    for host in a.all_hosts():
        b = a[host]['vendor']
        print('-' * 30)
        print(b)

        # print(f'Host: {host} - {b}')

        # for key in b:
        #     if b[key] == 'TPV Display Technology(Xiamen)':
        #         monitor = (host, b[key])
        #         print(monitor)
        #         return monitor

def test_1():
    # equipo = socket.gethostname()
    # IP = socket.gethostbyname(socket.gethostname())

    # print(socket)
    # s = nmap.PortScanner()
    # s.scan(hosts=IP+'/24', arguments='-sn')
    
    # for host in s.all_hosts():
    #     a = s[host]
    #     print(a)
    pass

def nmapper_2():
    ifConfig = subprocess.getoutput('ip route | grep default')
    split_1 = ifConfig.split('\n')[0]
    split_2 = split_1.split(' ')[2]
    a = nmap.PortScanner()
    a.scan(hosts=f'{split_2}/24', arguments='-sn')

    if a.all_hosts()[1] == '10.100.0.2':
        print(a.all_hosts()[0])
        return a.all_hosts()[0], 'OK'
    else: 
        print(a.all_hosts()[1])
        return a.all_hosts()[1], 'OK' 

def commands():
    HOST = nmapper_2()[0]
    PORT = 5000
    print(HOST)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            try:
                time.sleep(0.2)
                s.connect((HOST, PORT))
                s.sendall(bytes.fromhex('0501001511'))
                data = s.recv(1024)
                lon = len(data) - 1
                d = data[4:lon]
                if d == b'\x18':
                    print(f'-> Command not available, not relevant or cannot execute')
                elif d == b'\x15':
                    print(f'-> Not Acknowledge command')
                elif d == b'\x06':
                    print(f'- > Command applied succesfully')              
                else:
                    print(data[4:lon])

            except TimeoutError:
                print(f'-> Connection timeout')
    print('\n')
    # monitor_setting()
    pass
    
def prueba():
    print (monitors._Tiling['tiling_a'])

# commands()
# nmapper()
# nmapper_2()
# test_1()
prueba()