import socket, colorama, time, monitors, subprocess
from colorama import Fore
from nmap import nmap

def monitor_setting():
    # HOST = "127.0.0.1"  # The server's hostname or IP address
    # HOST = "192.168.137.16"  # The server's hostname or IP address
    # HOST = input('Host: ')

    # system('cls')

    opt = input('Select monitor:\n' + 
                '1- 43BDL4550D - BAT, Benzina\n' + 
                '2- 43BDL4550D - ITG Don Pealo\n' +
                '3- 32BDL4550D - BAT, Benzina\n' +
                '4- xxBDL2105X - Benzina VW\n')
    
    if opt == '1':
        monit = monitors._43BDL4550D_BAT_BEN
    if opt == '2':
        monit = monitors._43BDL4550D_ITG_DnP
    if opt == '3':
        monit = monitors._32BDL4550D_BAT_BEN
    if opt == '4':
        monit = monitors._xxBDL2105X
        monit['conf_pos'] = monitors._Tiling['tiling_a']
    #     position = input('Select position:\n' +
    #                      '1- A\n'+
    #                      '2- B\n'+
    #                      '3- C\n'+
    #                      '4- D\n'+
    #                      '5- R/L\n')
    #     if position == '1':
    #         monit['conf_pos'] = monitors._Tiling['tiling_a']
    #     if position == '2':
    #         monit['conf_pos'] = monitors._Tiling['tiling_b']
    #     if position == '3':
    #         monit['conf_pos'] = monitors._Tiling['tiling_c']
    #     if position == '4':
    #         monit['conf_pos'] = monitors._Tiling['tiling_d']
    print(monit)
    if opt == 'q':
        exit()


    HOST, Vendor = nmapper()
    PORT = 5000  # The port used by the server
    colorama.init(autoreset=True)
    print(f'Conected to {Vendor}')

    try:
        for i in monit:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                try:
                    time.sleep(0.5)
                    s.connect((HOST, PORT))
                    s.sendall(bytes.fromhex(monit[i]))
                    data = s.recv(1024)
                    lon = len(data) - 1
                    d = data[4:lon]
                    if d == b'\x18':
                        print(f'{Fore.RED}{i} -> Command not available, not relevant or cannot execute')
                    elif d == b'\x15':
                        print(f'{Fore.RED}{i} -> Not Acknowledge command')
                    elif d == b'\x06':
                        print(f'{Fore.GREEN}{i} - > Command applied succesfully')              
                    else:
                        print(data[4:lon])

                except TimeoutError:
                    print(f'{Fore.RED}{i} -> Connection timeout')
        print('\n')

        monitor_setting()
        
    except Exception as e:
        print (e)
        monitor_setting()


def nmapper():
    try:
        ifConfig = subprocess.getoutput('ip route | grep default')
        split_1 = ifConfig.split('\n')[0]
        split_2 = split_1.split(' ')[2]
        a = nmap.PortScanner()
        # a.scan(hosts='172.25.66.1/24', arguments='-sn')
        a.scan(hosts=f'{split_2}/24', arguments='-sn')
        
        # for host in a.all_hosts():
        #     b = a[host]['vendor']
            # for key in b:
            #     if b[key] == 'TPV Display Technology (Xiamen)' or b[key] == 'TPV Display Technology(Xiamen)':
            #         monitor = (host, b[key])
            #         return monitor

        if a.all_hosts()[1] == '10.100.0.2':
            print(a.all_hosts()[0])
            return a.all_hosts()[0], 'OK'
        else: 
            print(a.all_hosts()[1])
            return a.all_hosts()[1], 'OK' 
    except Exception as e:
        print(e)
        monitor_setting()
            

#####  Entry point ######
monitor_setting()
# nmapper()