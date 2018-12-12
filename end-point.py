import os
import osquery

instance = osquery.SpawnInstance()
instance.open()
#opens osquery for querying 

os.system('C:/Users/Administrator/Desktop/nc/nc.exe -nlvp 4444 > 1.txt')
#the system listens for an incoming ip address and will not do anything else until it recieves one


with open('1.txt') as f:
    x=f.readlines()
    x=str(x)
    z="select processes.name, process_open_sockets.remote_address, process_open_sockets.remote_port from process_open_sockets LEFT JOIN processes ON process_open_sockets.pid = processes.pid where remote_address ="+str(x)
    z=z.replace("[","")
    z=z.replace("]","")
    #file is opened and the ip address is read from the file. string manipulation is done to extract the ip address

    y=instance.client.query(z)
    #a query is sent to osquery to find the associated ip address with the process
    
    y=str(y)
    y=y.split(",")
    y=y[3]
    y=y.split("\'")
    y=y[3]
    #string manipulation is done to extract the process
    
    print (y)
    a='taskkill /F /IM '+y
    os.system(a)
    #a taskkill command is sent with the name of the process e.g. iexplore.exe
