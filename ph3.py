#!/usr/python
# Network Simulation Project
# Authors : Devendra Umbrajkar, Arpitha Anand, Palak Diwan
# take the input from the files; parse the packets ; regulate the input speed ; pass packet to classifier module
# consult local forwarding table and pass it to forwarding module

import time,struct,socket,threading,Queue,os,sys
from binascii import hexlify

start_time11=0
start_time12=0
start_time13=0
start_time21=0
start_time22=0
start_time23=0
start_time31=0
start_time32=0
start_time33=0
end_time11=0
end_time12=0
end_time13=0
end_time21=0
end_time22=0
end_time23=0
end_time31=0
end_time32=0
end_time33=0


r11=0
r12=0
r21=0
r22=0
r31=0
r32=0
r33=0
r13=0
r23=0
x1=0;x2=0;x3=0;x4=0;x5=0;x6=0;x7=0;x8=0;x9=0


res_i11=0
res_i12=0
res_i21=0
res_i22=0
res_i31=0
res_i32=0
res_i33=0
res_i13=0
res_i23=0
flag=0
ser_rate=[]
rate_1=[]
mean_l=[]
weight_q=[]
file_names=[]
arr_rate=[]
rate_temp=[]
rate=[]
data1=[]
data2=[]
data3=[]
total_packet_q1=0
total_packet_q2=0
total_packet_q3=0
list1=[]
list2=[]
list3=[]
ipr1=[]
ipr2=[]
ipr3=[]
temp=[]
ip1=[]
ip2=[]
ip3=[]
z=[]
outp=[]
ip_s=[]
ip_src=[]
out_port=[]
ipr_set=[]
ipr_list=[]
dest=[]
ip_main1=[]
ip_main2=[]
ip_main3=[]
sent_packet1=0
sent_packet2=0
sent_packet3=0
hexa_ver1=0
hexa_ver2=0
hexa_ver3=0
input_packet1=0
input_packet2=0
input_packet3=0
ver1=0
ver2=0
ver3=0
packet_q1=0
packet_q2=0
packet_q3=0
res2=0
res3=0
res1=0
summation=0
size_list=[]
size_h=0
cntr=0
size11=0
size12=0
size21=0
size22=0
size31=0
size32=0
size13=0
size23=0
size33=0
global q1,q2,q3
q1=Queue.Queue()
q2=Queue.Queue()
q3=Queue.Queue()
input_packet1=0
input_packet2=0
input_packet3=0
sent_packet1=0
sent_packet2=0
sent_packet3=0
q11=Queue.Queue()
q21=Queue.Queue()
q31=Queue.Queue()
q12=Queue.Queue()
q22=Queue.Queue()
q32=Queue.Queue()
packet_q11=0
packet_q12=0
packet_q21=0
packet_q22=0
packet_q31=0
packet_q32=0
end_time=0
out_queue=[]
q13=Queue.Queue()
q23=Queue.Queue()
q33=Queue.Queue()
packet_q13 =0
packet_q23 =0
packet_q33 =0
sentq11=0
sentq12=0
sentq13=0
sentq21=0
sentq22=0
sentq23=0
sentq31=0
sentq32=0
sentq33=0
iterate_packet_queue11=""
iterate_packet_queue12=""
iterate_packet_queue13=""
iterate_packet_queue21=""
iterate_packet_queue22=""
iterate_packet_queue23=""
iterate_packet_queue31=""
iterate_packet_queue32=""
iterate_packet_queue33=""


def find_speed():
    #cntr=0
    #num=cntr
    #cntr=cntr+1
    for k in range(0,9):
        s=500*arr_rate[k]
        rate_temp.append(s)
    min_sp=min(rate_temp)
    for k in range(0,9):
        rate.append(int(rate_temp[k]/min_sp))
    #return rate

def op_find_speed():
    global rate_temp
    m=0
    for x in range(0,3):
        sp=ser_rate[x]/(rate_temp[m] + rate_temp[m+1])
        rate_1.append(sp)
        m +=1
    #th=max(rate_1)
   # print rate_1
    #print th-rate_1[q]
    #return th-rate_1[q]


def copy_data(input):
    if(input==file_names[0]):
        read_file1()
    elif(input==file_names[1]):
        read_file2()
    else:
        read_file3()


def read_file1():
    print "read file 1"
    find_speed()
    op_find_speed()
    global first_line1,input_packet1,sent_packet1,packet_q1,packet_q2,packet_q3,ipr_list,ipr_set,end_time
    global data1,start_time,start_residence_time,packet_q32,packet_q22,packet_q21,packet_q31,packet_q11,packet_q12,ip_main1
    global start_time11,start_time12,start_time21,start_time22,start_time31,start_time32,cntr,ipr1,ipr2,ipr3
    global start_time13,start_time23,start_time33,packet_q33,packet_q23,packet_q13,end_time13,end_time23,end_time33
    #start_residence_time = time.clock()
    f=open(file_names[0],'rb')
    first_line1 = f.read()
    data1=map(''.join, zip(*[iter(first_line1)]*500))
    for i in range(0,len(data1)):
        ip_addr_h=hexlify(data1[i][16:20])   #read destination ip address from packet
        ip_addr_hex_a=ip_addr_h.ljust(8,'0')
        ip_addr_d=int(ip_addr_hex_a,16)      #decimal conversion
        ip1.append(socket.inet_ntoa(struct.pack("!L",ip_addr_d))) #convert to ip address form
        input_packet1 = input_packet1 + 1
    tmp=os.stat(forward_tab).st_size
    fs=tmp/22
    ft=open(forward_tab,'rb')
    frwrd_table=ft.read()
    for p in range(0,fs):
        list1=map(''.join, zip(*[iter(frwrd_table)]*22))
        ip_addr_hex=hexlify(list1[p][4:8])    #extract destination ip address from forwarding table
        ip_addr_hex_app=ip_addr_hex.ljust(8,'0')
        ip_addr_dec=int(ip_addr_hex_app,16)   #decimal conversion
        ipr1.append(socket.inet_ntoa(struct.pack("!L",ip_addr_dec)))   #convert to ip address from
        dest_addr_hex=hexlify(list1[p][8:12])  #extract destination mask from forwarding table
        dest_hex=dest_addr_hex.ljust(8,'0')
        dest_addr_dec=int(dest_hex,16)      #convert to decimal
        dest.append(socket.inet_ntoa(struct.pack("!L",dest_addr_dec)))   #convert to ip address form
        tcp_head_port = hexlify(list1[p][16:17])   #get the port number from the forwarding table
        tcp_head_port_dec=int(tcp_head_port,16)
        out_port.append(tcp_head_port_dec)
        out_que=hexlify(list1[p][17:18])             #get the output port queue number from the forwarding table
        out_q=int(out_que,16)
        out_queue.append(out_q)
        sent_packet1 = sent_packet1+1
    cntr=-1
    for i in range(0,len(ip1)):                   #iterate the loop to ip address we got from the packet
        start_time11=time.clock()
        start_time12=time.clock()
        start_time13=time.clock()

        start_time21=time.clock()
        start_time22=time.clock()
        start_time23=time.clock()

        start_time31=time.clock()
        start_time32=time.clock()
        start_time33=time.clock()

        for l in range(0,fs):
            ip_temp=struct.unpack('!L',socket.inet_aton(ip1[i]))[0]
            dest_temp=struct.unpack('!L',socket.inet_aton(dest[l]))[0]
            ip_and=ip_temp & dest_temp
            ip_main1.append(socket.inet_ntoa(struct.pack("!L",ip_and)))
    for i in range (0,len(ip_main1)):
        for l in range(0, fs):
            if(ip_main1[i]==ipr1[l]):          #check if ip address masked to destination mask stored.
                cntr += 1
                if(cntr<1500):
                    if(out_port[l]==1):
                        q1.put(data1[cntr])
                        packet_q1 += 1
                        if(out_queue[l]==1):
                            tem=max(rate)
                            r=tem-rate[0]
                            time.sleep(r/10)
                            te=q1.get()
                            q11.put(te)
                            packet_q11 +=1

                        elif(out_queue[l]==2):

                            tem=max(rate)
                            r=tem-rate[1]
                            time.sleep(r/10)
                            te=q1.get()
                            q12.put(te)
                            packet_q12 +=1

                        else:
                            tem=max(rate)
                            r=tem-rate[2]
                            time.sleep(r/10)
                            te=q1.get()
                            q13.put(te)
                            packet_q13 +=1

                    elif(out_port[l]==2):
                        q2.put(data1[cntr])
                        packet_q2 += 1
                        if(out_queue[l]==1):
                            tem=max(rate)
                            r=tem-rate[3]
                            time.sleep(r/10)
                            te=q2.get()
                            q21.put(te)
                            packet_q21 +=1
                        elif(out_queue[l] ==2):
                            tem=max(rate)
                            r=tem-rate[4]
                            time.sleep(r/10)
                            te=q2.get()
                            q22.put(te)
                            packet_q22 +=1

                        else:
                            tem=max(rate)
                            r=tem-rate[5]
                            time.sleep(r/10)
                            te=q2.get()
                            q23.put(te)
                            packet_q23 +=1

                    elif(out_port[l]==3):
                        q3.put(data1[cntr])
                        packet_q3 += 1
                        if(out_queue[l]==1):
                            tem=max(rate)
                            r=tem-rate[6]
                            time.sleep(r/10)
                            te=q3.get()
                            q31.put(te)
                            packet_q31 +=1

                        elif(out_queue[l]==2):
                            tem=max(rate)
                            r=tem-rate[7]
                            time.sleep(r/10)
                            te=q3.get()
                            q32.put(te)
                            packet_q32 +=1

                        else:
                            tem=max(rate)
                            r=tem-rate[8]
                            time.sleep(r/10)
                            te=q3.get()
                            q33.put(te)
                            packet_q33 +=1




    calc1()


def read_file2():
    print "read file 2"
    global first_line2,input_packet2,sent_packet2,packet_q1,packet_q2,packet_q3,ipr_list,ipr_set,end_time
    global data2,start_time,start_residence_time,packet_q11,packet_q12,packet_q32,packet_q22,packet_q21,packet_q31,ip_main2,cntr
    global start_time13,start_time23,start_time33,packet_q33,packet_q23,packet_q13,end_time13,end_time23,end_time33
    f = open(file_names[1], 'rb')
    first_line2 = f.read()
    start_residence_time = time.clock()
    data2=map(''.join, zip(*[iter(first_line2)]*500))
    for i in range(0,len(data2)):
        ip_addr_sh=hexlify(data2[i][12:16]) #read source ip address from packet
        ip_addr_sd=ip_addr_sh.ljust(8,'0')
        ip_addr_s=int(ip_addr_sd,16)        #decimal conversion
        ip_s.append(socket.inet_ntoa(struct.pack("!L",ip_addr_s)))   #convert to ip address form
        ip_addr_h=hexlify(data2[i][16:20])   #read destination ip address from packet
        ip_addr_hex_a=ip_addr_h.ljust(8,'0')
        ip_addr_d=int(ip_addr_hex_a,16)      #decimal conversion
        ip2.append(socket.inet_ntoa(struct.pack("!L",ip_addr_d))) #convert to ip address form
        input_packet2 = input_packet2 + 1
    tmp=os.stat(forward_tab).st_size
    fs=tmp/22
    ft=open(forward_tab,'rb')
    frwrd_table=ft.read()
    for p in range(0,fs):
        list2=map(''.join, zip(*[iter(frwrd_table)]*22))
        ip_addr_shex=hexlify(list2[p][0:4])   #extract source ip address from forwarding table
        ip_addr_sdec=ip_addr_shex.ljust(8,'0')
        ip_addr_src=int(ip_addr_sdec,16)      #decimal conversion
        ip_src.append(socket.inet_ntoa(struct.pack("!L",ip_addr_src)))  #convert to ip address form
        ip_addr_hex=hexlify(list2[p][4:8])    #extract destination ip address from forwarding table
        ip_addr_hex_app=ip_addr_hex.ljust(8,'0')
        ip_addr_dec=int(ip_addr_hex_app,16)   #decimal conversion
        ipr2.append(socket.inet_ntoa(struct.pack("!L",ip_addr_dec)))   #convert to ip address from
        dest_addr_hex=hexlify(list2[p][8:12])  #extract destination mask from forwarding table
        dest_hex=dest_addr_hex.ljust(8,'0')
        dest_addr_dec=int(dest_hex,16)      #convert to decimal
        dest.append(socket.inet_ntoa(struct.pack("!L",dest_addr_dec)))   #convert to ip address form
        tcp_head_port = hexlify(list2[p][16:17])   #get the port number from the forwarding table
        tcp_head_port_dec=int(tcp_head_port,16)
        out_port.append(tcp_head_port_dec)
        out_que=hexlify(list2[p][17:18])             #get the output port queue number from the forwarding table
        out_q=int(out_que,16)
        out_queue.append(out_q)
        sent_packet2 = sent_packet2+1
    cntr=-1
    for i in range(0,len(ip2)):                   #iterate the loop to ip address we got from the packet
        #for t in range(0,fs):                     #iterate the loop for the destination ip address from the forwarding table

    #start_time=time.clock()
    #cntr=0
   # for i in range(0,len(ip_main2)):
        for l in range(0,fs):
            ip_temp=struct.unpack('!L',socket.inet_aton(ip2[i]))[0]
            dest_temp=struct.unpack('!L',socket.inet_aton(dest[l]))[0]
            ip_and=ip_temp & dest_temp         #masking the ip address from the packet and destination address from the forwarding table
            ip_main2.append((socket.inet_ntoa(struct.pack("!L",ip_and))))  # store the mask address and convert it to ip form
    for i in range(0,len(ip_main2)):
        for l in range (0,fs):
            if(ip_main2[i]==ipr2[l]): #check if ip address masked to destination mask stored.
                cntr += 1
                #hexa_ver1=(bin(int(hexlify(data2[i][0]),16)))     #extract the 4 bits to check if ipv4 or ipv6
                #ver1=hexa_ver1[0:5]
                #if ver1 =="0b100":
                start_time=time.clock()
                if(cntr<1500):
                    if(out_port[l]==1):
                        q1.put(data2[cntr])
                        packet_q1 += 1
                        if(out_queue[l]==1):
                            tem=max(rate)
                            r=tem-rate[0]
                            time.sleep(r/10)
                            te=q1.get()
                            q11.put(te)
                            packet_q11 +=1

                        elif(out_queue[l]==2):
                            tem=max(rate)
                            r=tem-rate[1]
                            time.sleep(r/10)
                            te=q1.get()
                            q12.put(te)
                            packet_q12 +=1

                        else:
                            tem=max(rate)
                            r=tem-rate[2]
                            time.sleep(r/10)
                            te=q1.get()
                            q13.put(te)
                            packet_q13 +=1

                    elif(out_port[l]==2):
                        q2.put(data2[cntr])
                        packet_q2 += 1
                        if(out_queue[l]==1):
                            tem=max(rate)
                            r=tem-rate[3]
                            time.sleep(r/10)
                            te=q2.get()
                            q21.put(te)
                            packet_q21 +=1
                        elif(out_queue[l]==2):
                            tem=max(rate)
                            r=tem-rate[4]
                            time.sleep(r/10)
                            te=q2.get()
                            q22.put(te)
                            packet_q22 +=1
                        else:
                            tem=max(rate)
                            r=tem-rate[5]
                            time.sleep(r/10)
                            te=q2.get()
                            q23.put(te)
                            packet_q23 +=1

                    elif(out_port[l]==3):
                        q3.put(data2[cntr])
                        packet_q3 += 1
                        if(out_queue[l]==1):
                            tem=max(rate)
                            r=tem-rate[6]
                            time.sleep(r/10)
                            te=q3.get()
                            q31.put(te)
                            packet_q31 +=1
                        elif(out_queue[l]==2):
                            tem=max(rate)
                            r=tem-rate[7]
                            time.sleep(r/10)
                            te=q3.get()
                            q32.put(te)
                            packet_q32 +=1
                        else:
                            tem=max(rate)
                            r=tem-rate[8]
                            time.sleep(r/10)
                            te=q3.get()
                            q33.put(te)
                            packet_q33 +=1


    calc2()






def read_file3():
    print "in file 3"
    global first_line3,forward_tab,input_packet3,sent_packet3,packet_q1,packet_q2,packet_q3,ipr_list,ipr_set,end_time,start_time,start_residence_time
    global summation ,size_list,size,size_h,data3,packet_q11,packet_q12,packet_q21,packet_q22,packet_q31,packet_q32,ip_main3
    global start_time11,start_time12,start_time21,start_time22,start_time31,start_time32,start_time13,start_time33,start_time23
    global end_time11,end_time12,end_time21,end_time22,end_time31,end_time32,end_time33,end_time23,end_time13
    global r11,r22,r32,r12,r21,r31,res_i11,res_i12,res_i21,res_i22,res_i31,res_i32,x1,x2,x3,x4,x5,x6,size11,size12,size21,size22,size31,size,cntr
    global size13,size23,size33,sentq11,sentq12,sentq13,sentq21,sentq22,sentq23,sentq31,sentq32,sentq33,x7,x8,x9
    global iterate_packet_queue11,iterate_packet_queue12,iterate_packet_queue13,iterate_packet_queue21,iterate_packet_queue22
    global iterate_packet_queue23,iterate_packet_queue31,iterate_packet_queue32,iterate_packet_queue33
    global packet_q13,packet_q23,packet_q33
    f = open(file_names[2], 'rb')
    first_line3 = f.read()
    start_residence_time = time.clock()
    data3=map(''.join, zip(*[iter(first_line3)]*500))
    for i in range(0,len(data3)):
        ip_addr_sh=hexlify(data3[i][12:16]) #read source ip address from packet
        ip_addr_sd=ip_addr_sh.ljust(8,'0')
        ip_addr_s=int(ip_addr_sd,16)        #decimal conversion
        ip_s.append(socket.inet_ntoa(struct.pack("!L",ip_addr_s)))   #convert to ip address form
        ip_addr_h=hexlify(data3[i][16:20])   #read destination ip address from packet
        ip_addr_hex_a=ip_addr_h.ljust(8,'0')
        ip_addr_d=int(ip_addr_hex_a,16)      #decimal conversion
        ip3.append(socket.inet_ntoa(struct.pack("!L",ip_addr_d))) #convert to ip address form
        input_packet3 = input_packet3 + 1
    tmp=os.stat(forward_tab).st_size
    fs=tmp/22
    ft=open(forward_tab,'rb')
    frwrd_table=ft.read()
    for p in range(0,fs):
        list3=map(''.join, zip(*[iter(frwrd_table)]*22))
        ip_addr_shex=hexlify(list3[p][0:4])   #extract source ip address from forwarding table
        ip_addr_sdec=ip_addr_shex.ljust(8,'0')
        ip_addr_src=int(ip_addr_sdec,16)      #decimal conversion
        ip_src.append(socket.inet_ntoa(struct.pack("!L",ip_addr_src)))  #convert to ip address form
        ip_addr_hex=hexlify(list3[p][4:8])    #extract destination ip address from forwarding table
        ip_addr_hex_app=ip_addr_hex.ljust(8,'0')
        ip_addr_dec=int(ip_addr_hex_app,16)   #decimal conversion
        ipr3.append(socket.inet_ntoa(struct.pack("!L",ip_addr_dec)))   #convert to ip address from
        dest_addr_hex=hexlify(list3[p][8:12])  #extract destination mask from forwarding table
        dest_hex=dest_addr_hex.ljust(8,'0')
        dest_addr_dec=int(dest_hex,16)      #convert to decimal
        dest.append(socket.inet_ntoa(struct.pack("!L",dest_addr_dec)))   #convert to ip address form
        tcp_head_port = hexlify(list3[p][16:17])   #get the port number from the forwarding table
        tcp_head_port_dec=int(tcp_head_port,16)
        out_port.append(tcp_head_port_dec)
        out_que=hexlify(list3[p][17:18])             #get the output port queue number from the forwarding table
        out_q=int(out_que,16)
        out_queue.append(out_q)
        sent_packet3 = sent_packet3+1
    cntr=-1
    for i in range(0,len(ip3)):                   #iterate the loop to ip address we got from the packet
        #for t in range(0,fs):                     #iterate the loop for the destination ip address from the forwarding table

    #start_time=time.clock()

    #for i in range(0,len(ip_main3)):
        for l in range(0,fs):
            ip_temp=struct.unpack('!L',socket.inet_aton(ip3[i]))[0]
            dest_temp=struct.unpack('!L',socket.inet_aton(dest[l]))[0]
            ip_and=ip_temp & dest_temp         #masking the ip address from the packet and destination address from the forwarding table
            ip_main3.append((socket.inet_ntoa(struct.pack("!L",ip_and))))  # store the mask address and convert it to ip form
    for i in range(0,len(ip_main3)):
        for l in range (0,fs):
            if(ip_main3[i]==ipr3[l]):          #check if ip address masked to destination mask stored.
                cntr += 1
                if(cntr<1500):
                    if(out_port[l]==1):
                        q1.put(data3[cntr])
                        packet_q1 += 1
                        if(out_queue[l]==1):
                            tem=max(rate)
                            r=tem-rate[0]
                            time.sleep(r/10)
                            te=q1.get()
                            q11.put(te)
                            packet_q11 +=1
                        elif(out_queue[l]==2):
                            tem=max(rate)
                            r=tem-rate[1]
                            time.sleep(r/10)
                            te=q1.get()
                            q12.put(te)
                            packet_q12 +=1
                        else:
                            tem=max(rate)
                            r=tem-rate[2]
                            time.sleep(r/10)
                            te=q1.get()
                            q13.put(te)
                            packet_q13 +=1

                    elif(out_port[l]==2):
                        q2.put(data3[cntr])
                        packet_q2 += 1
                        if(out_queue[l]==1):
                            tem=max(rate)
                            r=tem-rate[3]
                            time.sleep(r/10)
                            te=q2.get()
                            q21.put(te)
                            packet_q21 +=1
                        elif(out_queue[l] ==2):
                            tem=max(rate)
                            r=tem-rate[4]
                            time.sleep(r/10)
                            te=q2.get()
                            q22.put(te)
                            packet_q22 +=1
                        else:
                            tem=max(rate)
                            r=tem-rate[5]
                            time.sleep(r/10)
                            te=q2.get()
                            q23.put(te)
                            packet_q23 +=1

                    elif(out_port[l]==3):
                        q3.put(data3[cntr])
                        packet_q3 += 1
                        if(out_queue[l]==1):
                            tem=max(rate)
                            r=tem-rate[6]
                            time.sleep(r/10)
                            te=q3.get()
                            q31.put(te)
                            packet_q31 +=1
                        elif(out_queue[l]==2):
                            tem=max(rate)
                            r=tem-rate[7]
                            time.sleep(r/10)
                            te=q3.get()
                            q32.put(te)
                            packet_q32 +=1
                        else:
                            tem=max(rate)
                            r=tem-rate[8]
                            time.sleep(r/10)
                            te=q3.get()
                            q33.put(te)
                            packet_q33 +=1



    while q12.qsize()!=0 or q11.qsize()!=0 or q13.qsize()!=0:
        #print "hello"
        th=max(rate_1)
        oe=th-rate_1[1]
            #q11 will continue until it is empty and copy into the file o11
        if q11.qsize() != 0:
            if(q11.qsize() > size11):
                size11 = q11.qsize()
                x1+=1
            #print x1
            for q in range(0,weight_q[0]):
                try:
                    iterate_packet_queue11 = q11.get()
                    sentq11 += 1
                    iterate_packet_queue11 += iterate_packet_queue11
                    break
                except q11.empty():
                    continue
            f1=open('o11','a')
            time.sleep(oe/10)
            f1.write(iterate_packet_queue11)
        end_time11=time.clock()

        if q12.qsize() != 0:
            if(q12.qsize() > size12):
                size12 = q12.qsize()
                x2+=1
            for q in range (0,weight_q[1]):
                try:
                    iterate_packet_queue12 = q12.get()
                    sentq12 += 1
                    iterate_packet_queue12 += iterate_packet_queue12
                    break
                except q12.empty():
                    continue
            f1=open('o11','a')
            time.sleep(oe/10)
            f1.write(iterate_packet_queue12)
        end_time12=time.clock()

        if q13.qsize() !=  0:
            if(q13.qsize() > size13):
                size13 = q13.qsize()
                x3+=1
            for q in range (0,weight_q[2]):
                try:
                    iterate_packet_queue13 = q13.get()
                    sentq13 += 1
                    iterate_packet_queue13 += iterate_packet_queue13
                    break
                except q13.empty():
                    continue

            f1=open('o11','a')
            time.sleep(oe/10)
            f1.write(iterate_packet_queue13)
        end_time13=time.clock()


    while q21.qsize()!=0 or q22.qsize()!=0 or q23.qsize()!=0 :
        th=max(rate_1)
        oe=th-rate_1[2]
        if q21.qsize()!= 0:
            if(q21.qsize() > size21):
                size21 = q21.qsize()
                x4+=1
            for q in range (0,weight_q[3]):
                try:
                    iterate_packet_queue21 = q21.get()
                    sentq21 += 1
                    iterate_packet_queue21 += iterate_packet_queue21
                    break
                except q21.empty():
                    continue
            f2=open('o22','a')
            time.sleep(oe/10)
            f2.write(iterate_packet_queue21)
        end_time21=time.clock()

        if q22.qsize() != 0:
            if(q22.qsize() > size22):
                size22 = q22.qsize()
                x5+=1
            for q in range (0,weight_q[4]):
                try:
                    iterate_packet_queue22 = q22.get()
                    sentq22 += 1
                    iterate_packet_queue22 += iterate_packet_queue22
                    break
                except q22.empty():
                    continue
                    #break

            f2=open('o22','a')
            time.sleep(oe/10)
            f2.write(iterate_packet_queue22)
        end_time22=time.clock()

        if q23.qsize() != 0:
            if(q23.qsize() > size23):
                size23 = q23.qsize()
                x6+=1
            for q in range (0,weight_q[5]):
            #if (sentq23!= weight_q[2]):
                iterate_packet_queue23 = q23.get()
                sentq23 += 1
                #print sentq23
                iterate_packet_queue23 += iterate_packet_queue23
            f2=open('o22','a')
            time.sleep(oe/10)
            f1.write(iterate_packet_queue23)
        end_time23=time.clock()

    while q31.qsize()!=0 or q32.qsize()!=0 or q33.qsize()!=0 :
        th=max(rate_1)
        oe=th-rate_1[2]
        #print"hello"
        if q31.qsize() != 0:
            if(q31.qsize() > size31):
                size31 = q31.qsize()
                x7+=1
            for q in range (0,weight_q[6]):
                try:
                    iterate_packet_queue31 = q31.get()
                    sentq31 += 1
                    iterate_packet_queue31 += iterate_packet_queue31
                except q31.empty():
                    break


            f3=open('o33','a')
            time.sleep(oe/10)
            f3.write(iterate_packet_queue31)
        end_time31=time.clock()

        if q32.qsize() != 0:
            if(q32.qsize() > size32):
                size32 = q32.qsize()
                x8+=1
            for q in range (0,weight_q[7]):
                try:
                    iterate_packet_queue32 = q32.get()
                    sentq32 += 1
                    iterate_packet_queue32 += iterate_packet_queue32
                    break
                except q32.empty():
                    continue

            f3=open('o33','a')
            time.sleep(oe/10)
            f3.write(iterate_packet_queue32)
        end_time32=time.clock()

        if q33.qsize()!=0:
            if(q33.qsize() > size33):
                size33 = q33.qsize()
                x9+=1
            for q in range (0,weight_q[8]):
                try:
                    iterate_packet_queue33 = q33.get()
                    sentq33 += 1
                    iterate_packet_queue33 += iterate_packet_queue33
                except q33.empty():
                    break

                iterate_packet_queue33 += iterate_packet_queue33
            f3=open('o33','a')
            time.sleep(oe/10)
            f3.write(iterate_packet_queue33)
        end_time33=time.clock()

    calc3()

def calc1():
    global end_time,end_residence_time,start_time,packet_q1,packet_q2,packet_q3,total_packet,res1,res2,res3,service_rate1
    global service_rate2,service_rate3,utilization1,utilization2,utilization3,total_packet_q1,total_packet_q2,total_packet_q3
    total_packet_q1=packet_q1
    total_packet_q2=packet_q2
    total_packet_q3=packet_q3

def calc2():
    global end_time,end_residence_time,start_time,packet_q1,packet_q2,packet_q3,total_packet,res1,res2,res3,service_rate1
    global service_rate2,service_rate3,utilization1,utilization2,utilization3,total_packet_q1,total_packet_q2,total_packet_q3
    total_packet_q1 += packet_q1
    total_packet_q2 += packet_q2
    total_packet_q3 += packet_q3


def calc3():
    global end_time,end_residence_time,start_time,packet_q1,packet_q2,packet_q3,total_packet,res1,res2,res3,service_rate1
    global service_rate2,service_rate3,utilization1,utilization2,utilization3,total_packet_q1,total_packet_q2,total_packet_q3
    global res11,res12,res21,res22,res31,res32,residence_time,x7,x8,x9,r13,r23,r33,size13,size23,size33,res_i33,res_i23,res_i13
    global r11,r22,r32,r12,r21,r31,res_i11,res_i12,res_i21,res_i22,res_i31,res_i32,x1,x2,x3,x4,x5,x6,size11,size12,size21,size22,size31,size32
    global packet_q11,packet_q12,packet_q13,packet_q21,packet_q22,packet_q23,packet_q31,packet_q32,packet_q33
    global start_time11,start_time12,start_time13,start_time21,start_time22,start_time23,start_time31,start_time32,start_time33
    global end_time11,end_time12,end_time13,end_time21,end_time21,end_time22,end_time23,end_time31,end_time32,end_time33
    a=912;b=613;c=276;d=609;e=297;f=614;g=594;h=293;i=292

    if(x1!=0):
        r11= size11/x1
    if(x2!=0):
        r12= size12/x2
    if(x3!=0):
        r13= size13/x3
    if(x4!=0):
        r21= size21/x4
    if(x5!=0):
        r22= size22/x5
    if(x6!=0):
        r23= size23/x6
    if(x7!=0):
        r31= size31/x7
    if(x8!=0):
        r32= size32/x8
    if(x9!=0):
        r33= size33/x6

    res11=end_time11-start_time11
    res12=end_time12-start_time12
    res13=end_time13-start_time13
    res21=end_time21-start_time21
    res22=end_time22-start_time22
    res23=end_time23-start_time23
    res31=end_time31-start_time31
    res32=end_time32-start_time32
    res33=end_time33-start_time33
    if(packet_q11!=0):
        res_i11=res11/packet_q11
    if(packet_q12 !=0):
        res_i12=res12/packet_q12
    if(packet_q13 !=0):
        res_i13=res12/packet_q13
    if(packet_q21!=0):
        res_i21=res21/packet_q21
    if(packet_q22!=0):
        res_i22=res22/packet_q22
    if(packet_q23!=0):
        res_i23=res23/packet_q23
    if(packet_q31!=0):
        res_i31=res31/packet_q31
    if(packet_q32!=0):
        res_i32=res32/packet_q32
    if(packet_q33!=0):
        res_i33=res33/packet_q33
    print "Packet Sent to input queue 1 is %s"%packet_q1
    print "Packet Sent to input queue 2 is %s"%packet_q2
    print "Packet Sent to input queue 3 is %s"%packet_q3
    print "Packet Sent to output port1 queue 1 is %s"%packet_q11
    print "Packet Sent to output port1 queue 2 is %s"%packet_q12
    print "Packet Sent to output port1 queue 3 is %s"%packet_q13

    print "Packet Sent to output port2 queue 1 is %s"%packet_q21
    print "Packet Sent to output port2 queue 2 is %s"%packet_q22
    print "Packet Sent to output port2 queue 3 is %s"%packet_q23

    print "Packet Sent to output port3 queue 1 is %s"%packet_q31
    print "Packet Sent to output port3 queue 2 is %s"%packet_q32
    print "Packet Sent to output port1 queue 3 is %s"%packet_q33

    print "Mean number of Packet Resident in output port1 queue 1 is %s"%r11
    print "Mean number of Packet Resident in output port1 queue 2 is %s"%r12
    print "Mean number of Packet Resident in output port1 queue 3 is %s"%r13
    print "Mean number of Packet Resident in output port2 queue 1 is %s"%r21
    print "Mean number of Packet Resident in output port2 queue 2 is %s"%r22
    print "Mean number of Packet Resident in output port2 queue 3 is %s"%r23
    print "Mean number of Packet Resident in output port3 queue 1 is %s"%r31
    print "Mean number of Packet Resident in output port3 queue 2 is %s"%r32
    print "Mean number of Packet Resident in output port3 queue 3 is %s"%r33

    print "Number of packets resident for port 1 queue 1 is %s"%size11
    print "Number of packets resident for port 1 queue 2 is %s"%size12
    print "Number of packets resident for port 1 queue 3 is %s"%size13
    print "Number of packets resident for port 2 queue 1 is %s"%size21
    print "Number of packets resident for port 2 queue 2 is %s"%size22
    print "Number of packets resident for port 2 queue 3 is %s"%size23
    print "Number of packets resident for port 3 queue 1 is %s"%size31
    print "Number of packets resident for port 3 queue 2 is %s"%size32
    print "Number of packets resident for port 3 queue 3 is %s"%size33

    print "Residence time for port 1 queue1 is %s"%res11
    print "Residence time for port 1 queue2 is %s"%res12
    print "Residence time for port 1 queue2 is %s"%res13

    print "Residence time for port 2 queue1 is %s"%res21
    print "Residence time for port 2 queue2 is %s"%res22
    print "Residence time for port 2 queue2 is %s"%res23

    print "Residence time for port 3 queue1 is %s"%res31
    print "Residence time for port 3 queue2 is %s"%res32
    print "Residence time for port 3 queue2 is %s"%res33

    print "Residence time for individual packet port 1 queue1 is %s"%res_i11
    print "Residence time for individual packet port 1 queue2 is %s"%res_i12
    print "Residence time for individual packet port 1 queue3 is %s"%res_i13

    print "Residence time for individual packet port 2 queue1 is %s"%res_i21
    print "Residence time for individual packet port 2 queue2 is %s"%res_i22
    print "Residence time for individual packet port 2 queue3 is %s"%res_i23

    print "Residence time for individual packet port 3 queue1 is %s"%res_i31
    print "Residence time for individual packet port 3 queue2 is %s"%res_i32
    print "Residence time for individual packet port 3 queue3 is %s"%res_i33

    #print "Number of packets for port 3 is %s"%input_packet3
    #print "Packet Sent to queue 1 is %s"%packet_q1
    #print "Packet Sent to queue 2 is %s"%packet_q2
    #print "Packet Sent to queue 3 is %s"%packet_q3
    #print "Residence time for queue 3 is %s"%res3
    #print "Residence Packet for queue 3 is %s"%sent_packet3
    #print "Arrival Rate for queue 3 is %s"%arrival_rate3
    #print "Service Rate for queue 3 is %s"%service_rate3
    #print "Maximum Residence time for an individual packet is %s"%residence_time
    total_packet_q1 += packet_q1
    print total_packet_q1
    total_packet_q2 += packet_q2
    print total_packet_q2
    total_packet_q3 += packet_q3
    print total_packet_q3






def ip_threads(name,delay,repeat):
    tlock = threading.Lock()
    tlock.acquire()
    while repeat>0:
        time.sleep(delay)
        copy_data(name)
        repeat -=1
    tlock.release()


def Main():
    global file_names,arr_rate,mean_l,forward_tab,ser_rate
    for i in range(0,3):
        f_name=raw_input("Enter the file name")
        file_names.append(f_name)
        for j in range(0,3):
            arr_rate.append(arr)
            weight = int(raw_input("enter the weight for queue %s:" %j))
            weight_q.append(weight)
        ser=int(raw_input("Enter the service rate for each queue:"))
        ser_rate.append(ser)
    forward_tab=raw_input("Enter the name of file for forwarding table")
    import threading
    t1 = threading.Thread(target=ip_threads,args=(file_names[0],5,1))
    t2 = threading.Thread(target =ip_threads,args=(file_names[1],10,1))
    t3 = threading.Thread(target =ip_threads,args=(file_names[2],15,1))
    arr=int(raw_input("Enter the arrival rate:"))
    t1.start()
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()


if __name__ == '__main__':
    Main()
