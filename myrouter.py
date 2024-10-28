#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *
from switchyard.lib.packet import *
import threading
import queue

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.interfaces=net.interfaces()
        self.ip_list=[i.ipaddr for i in self.interfaces]
        self.mac_list=[i.ethaddr for i in self.interfaces]
        self.port_list=[intf.name for intf in self.interfaces]
        self.arp_cache={}
        self.time=0
        self.forwarding_table=[]
        self.init_forwarding_table()
        self.dataqueue=[]#the data coordinate with arprequest
        self.spectime=0
        self.arprequestsend={}




    
    def init_forwarding_table(self):
        for item in self.interfaces:
            ip=item.ipaddr
            mask=item.netmask
            next_hop=IPv4Address('0.0.0.0')
            port_name=item.name
            self.forwarding_table.append([ip,mask,next_hop,port_name])
        with open("forwarding_table.txt") as file:
            for line in file:
                parts=line.strip().split()
                ip,mask,next_hop,port_name=parts
                ip=IPv4Address(ip)
                mask=IPv4Address(mask)
                next_hop=IPv4Address(next_hop)
                self.forwarding_table.append([ip,mask,next_hop,port_name])

    def find_interface(self,dst_ip):
        index=None
        max_match=0
        dst_ip=IPv4Address(dst_ip)
        for item in self.forwarding_table:
            
            tempnetaddr=IPv4Network(f'{item[0]}/{item[1]}',strict=False)
            if dst_ip in tempnetaddr:
                if tempnetaddr.prefixlen>max_match:
                    max_match=tempnetaddr.prefixlen
                    index=item
        return index


        # other initialization stuff here
    def send_arprequest(self, targetip, iface_name, packet):
        
        if targetip in self.arprequestsend:
            self.dataqueue.append({"arp": targetip, "iface": iface_name, "data": packet})
            return

        
        self.arprequestsend[targetip] = {"iface": iface_name, "retries": 1, "last_sent": time.time()}
        iface = self.net.interface_by_name(iface_name)
        arp_request = create_ip_arp_request(iface.ethaddr, iface.ipaddr, targetip)
        self.net.send_packet(iface_name, arp_request)
        print(f"{targetip} has sent arp request")

        
        self.dataqueue.append({"arp": targetip, "iface": iface_name, "data": packet})

    def arp_respond_loop(self):
        current_time = time.time()
        for targetip, info in list(self.arprequestsend.items()):
            
            if current_time - info["last_sent"] >= 1:
                if info["retries"] >= 5:
                   
                    print(f"ARP 请求超过5次失败，删除目标 IP：{targetip}")
                    del self.arprequestsend[targetip]
                   
                    self.dataqueue = [entry for entry in self.dataqueue if entry["arp"] != targetip]
                else:
                    
                    iface_name = info["iface"]
                    iface = self.net.interface_by_name(iface_name)
                    arp_request = create_ip_arp_request(iface.ethaddr, iface.ipaddr, targetip)
                    self.net.send_packet(iface_name, arp_request)
                    info["retries"] += 1
                    info["last_sent"] = current_time
                    print(f"{targetip} 第 {info['retries']} 次重发 ARP 请求")
            

        
    def handle_arp(self,arp,iface_name):
        if arp.targetprotoaddr not in self.ip_list:
            print("not for me")
            return 
        if arp.operation==ArpOperation.Request:
            
            self.arp_cache[arp.senderprotoaddr]=[arp.senderhwaddr,time.time()]
                
            if arp.operation==ArpOperation.Request:
                reply_mac=self.mac_list[self.ip_list.index(arp.targetprotoaddr)]
                reply_packet=create_ip_arp_reply(reply_mac,arp.senderhwaddr,
                    arp.targetprotoaddr,arp.senderprotoaddr)
                self.net.send_packet(iface_name,reply_packet)

        elif arp.operation==ArpOperation.Reply:
            if arp.targethwaddr==EthAddr('ff:ff:ff:ff:ff:ff') or arp.senderhwaddr==EthAddr('ff:ff:ff:ff:ff:ff'):
                log_info(f'ARP reply is not allowed')
                return 
            self.arp_cache[arp.senderprotoaddr]=[arp.senderhwaddr,time.time()]
            for item in list(self.dataqueue):
                # 检查等待 ARP 响应的 IP 和接口是否匹配
                if item["arp"] == arp.senderprotoaddr and item["iface"] == iface_name:
                    packet = item["data"]
                    eth = packet.get_header(Ethernet)
                    eth.dst = arp.senderhwaddr
                    eth.src = self.net.interface_by_name(iface_name).ethaddr
                    self.net.send_packet(iface_name, packet)
                    # 从 dataqueue 中删除已发送的数据包
                    self.dataqueue.remove(item)

  
            if arp.senderprotoaddr in self.arprequestsend:
                del self.arprequestsend[arp.senderprotoaddr]





    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp=packet.get_header(Arp)
        icmp=packet.get_header(ICMP)
        eth=packet.get_header(Ethernet)
        ipv4=packet.get_header(IPv4)
        for ip_addr in list(self.arp_cache.keys()):
            if time.time() - self.arp_cache[ip_addr][1] >= 100.0:
                del self.arp_cache[ip_addr]
        if eth.dst not in self.mac_list and eth.dst!="ff:ff:ff:ff:ff:ff":
            log_info("如果以太网目标既不是广播地址也不是传入端口的 MAC，则路由器应始终丢弃它，而不是执行查找过程。")
            return 
        if eth.dst!='ff:ff:ff:ff:ff:ff' and self.port_list[self.mac_list.index(eth.dst)]!=ifaceName:
            log_info(f'throw ')
            return
        if packet[Ethernet].ethertype == EtherType.VLAN:
            log_info(f'throw packet with vlan')
            return
        if arp:
            self.handle_arp(arp,ifaceName)
            return 
        if ipv4:
            dst_ip=ipv4.dst
            if dst_ip in self.ip_list:
                log_info("如果数据包是针对路由器本身的（即目标地址位于路由器的接口之间），则只需丢弃/忽略该数据包。我们也将在 Lab 5 中处理这个问题。")
                return
            index=self.find_interface(dst_ip)
            if index is None:
                log_info("如果表中没有匹配项，请暂时丢弃数据包。我们将在实验 5 中处理此问题。")
                return
            else:
                #print(self.arp_cache)
                ipv4.ttl-=1
                if index[2]==IPv4Address('0.0.0.0'):
                    next_hop_ip=ipv4.dst
                else:
                    next_hop_ip=index[2] 
                if ipv4.src==IPv4Address('31.0.1.1'):
                    print(ipv4.dst)
                iface_name=index[3]
                if next_hop_ip in self.arp_cache:
                    with open("file.txt","a") as file:
                        file.write(str(next_hop_ip)+'\n')
                        file.close
                    next_hop_mac=self.arp_cache[next_hop_ip][0]
                    eth.dst=next_hop_mac
                    eth.src=self.net.interface_by_name(iface_name).ethaddr
                    self.net.send_packet(iface_name,packet)
                else:
                    self.send_arprequest(next_hop_ip,iface_name,packet)
                    print(f"find next but no mac{next_hop_ip}")

            


        



    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            
            try:
                recv = self.net.recv_packet(timeout=1)    
            except NoPackets:
                self.arp_respond_loop()
                continue
            except Shutdown:
                break
            self.handle_packet(recv)
            self.arp_respond_loop()
            
            

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()