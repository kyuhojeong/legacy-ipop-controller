#!/usr/bin/env python

import observer
import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

from ryu.controller import dpset

import commands
import fcntl
import imp
import json
import random
import socket
import threading
import select
import struct
import sys
import time

 
import ryu.controller.dpset

#-----------------------------------------------------------------------------
# CONFIGURATION
#-----------------------------------------------------------------------------

# TODO - multiple WAN interface support
WAN_IF_NAME = "eth0"
BRIDGE_NAME = "nat-br"
GATEWAY_IP  = "192.168.4.1"
HOST_IP = None
LAN_SUBNET_RANGE = 24
IPOP_STARTS = True
#IPOP_CONFIG_COMMAND_LINE = ["-c", "config.json", "-i"]
IPOP_CONFIG_COMMAND_LINE = ["-c", "config.json"]
IPOP_TAP_INTERFACE_NAME = "ipop"
IPOP_TINCAN_BINARY_PATH = "/home/kyuho/Workspace/libjingle/trunk/out/Release/ipop-tincan"
IPOP_CONTROLLER_PATH = "/home/kyuho/Workspace/controllers/src/"

def getHwAddr(ifname): 
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

# Change string form IPv4 to binary form
def ip4_a2b(str_ip4):
    return "".join(chr(int(x)) for x in str_ip4.split('.'))

# Change binary form IPv4 to string form
def ip4_b2a(bin_ip4):
    return "".join(str(ord(bin_ip4[x])) + "." for x in range (0,3)) \
           + str(ord(bin_ip4[3]))

# Change string form IPv4 to integer
def ip4_a2i(string):
    ip = string.split('.')
    assert len(ip) == 4
    i = 0
    for b in ip:
        b = int(b)
        i = (i << 8) | b
    return i

# Convert hex string such as("0113F40A") to 10.244.19.1. It also converts 
# network order to host order
def ip4_h2a(bin_ip4):
    return "".join(str(int(bin_ip4[x:x+2], 16)) + "." for x in range (6,0, -2))\
           + str(int(bin_ip4[0:2], 16))

# Change binary form of MAC address to string form
def mac_a2b(str_mac):
    return "".join(x.decode("hex") for x in str_mac.split(':'))

def mac_b2a(bin_mac):
    return "".join(bin_mac[x].encode("hex") + ":" for x in range(0,5)) +\
           bin_mac[5].encode("hex")

# Convert word(4 byte) to integer 
def w2i(word):
    return (ord(word[0]) << 24) + (ord(word[1]) << 16) + (ord(word[2]) << 8) + ord(word[3])

# Convert short(two bytes) to integer
def s2i(short):
    return (ord(short[0]) << 8) + ord(short[1])

# Receives byte stream and return checksum. Byte stream should be order of 4
# This function assume sum + carry does not overflow
def checksum(data):
    if (len(data) % 2) != 0 :
        raise Exception 
    full_sum = sum([s2i(data[i:i+2]) for i in range(0, len(data), 2)])
    carry = full_sum >> 16
    half_sum = full_sum & 0xffff
    checksum = (half_sum + carry) ^ 0xffff
    checksum_high = checksum / 256
    checksum_low = checksum & 0xff
    ret = chr(checksum_high) + chr(checksum_low)
    return ret

# Takes two string format IPv4 address and return True if they are in same
# subnet range
def is_in_subnet(a, b, subnet):
    aa = ip4_a2i(a)
    bb = ip4_a2i(b)
    tenbus = 32 - subnet
    return ((aa >> tenbus) == (bb >> tenbus))

class OpenflowControllerSlot(observer.Observer):
    #def __init__(self, CONFIG_):
    def __init__(self, observable, natswitch):
        super(OpenflowControllerSlot, self).__init__("ocs")
        self.observable = observable
        self.observable.register(self) 
        self.natswitch = natswitch
        print("Slot has been initialized")

    def on_message(self, msg_type, msg):
        print("on_message type:{0} message:{1}".format(msg_type, msg))
        if msg["type"] == "packet_notify_local_inbound":
            self.natswitch.insert_host_to_guest_flow(\
              src_host_ip4=msg["remote_host_ipv4"],\
              #dst_host_ip4=msg["local_host_ipv4"],\
              dst_host_ip4=HOST_IP,\
              nw_proto=msg["nw_proto"],\
              src_host_tp=msg["dst_random_port"],\
              dst_host_tp=msg["src_random_port"],\
              src_guest_tp=msg["dst_port"],\
              dst_guest_tp=msg["src_port"],\
              dst_mac=msg["src_mac"],\
              src_guest_ip4=msg["dst_ipv4"],\
              dst_guest_ip4=msg["src_ipv4"])
        if msg["type"] == "packet_notify_local_outbound":
            self.natswitch.insert_guest_to_host_flow(
              src_guest_ip4=msg["src_ipv4"],\
              dst_guest_ip4=msg["dst_ipv4"],\
              nw_proto=msg["nw_proto"],\
              src_guest_tp=msg["src_port"],\
              dst_guest_tp=msg["dst_port"],\
              dst_host_ip4=msg["remote_host_ipv4"],\
              #src_host_ip4=msg["local_host_ipv4"],\
              src_host_ip4=HOST_IP,\
              src_host_tp=msg["src_random_port"],\
              dst_host_tp=msg["dst_random_port"])
        elif msg["type"] == "packet_notify_remote":
            self.natswitch.insert_host_to_guest_flow(\
              src_host_ip4=msg["local_host_ipv4"],\
              #dst_host_ip4=msg["remote_host_ipv4"],\
              dst_host_ip4=HOST_IP,\
              nw_proto=msg["nw_proto"],\
              src_host_tp=msg["src_random_port"],\
              dst_host_tp=msg["dst_random_port"],\
              src_guest_tp=msg["src_port"],\
              dst_guest_tp=msg["dst_port"],\
              dst_mac=msg["dst_mac"],\
              src_guest_ip4=msg["src_ipv4"],\
              dst_guest_ip4=msg["dst_ipv4"])
            self.natswitch.insert_guest_to_host_flow(
              src_guest_ip4=msg["dst_ipv4"],\
              dst_guest_ip4=msg["src_ipv4"],\
              nw_proto=msg["nw_proto"],\
              src_guest_tp=msg["dst_port"],\
              dst_guest_tp=msg["src_port"],\
              dst_host_ip4=msg["local_host_ipv4"],\
              #src_host_ip4=msg["remote_host_ipv4"],\
              src_host_ip4=HOST_IP,\
              src_host_tp=msg["dst_random_port"],\
              dst_host_tp=msg["src_random_port"])
        #if msg["type"] == "packet_notify_local":
        #    self.natswitch.insert_packet_translate_flow_entry(\
        #      src_mac=msg["src_mac"], nw_proto=msg["nw_proto"],\
        #      src_ipv4=msg["src_ipv4"], src_transport=msg["src_port"],\
        #      src_random_tp=msg["src_random_port"],\
        #      dst_random_tp=msg["dst_random_port"],\
        #      dst_guest_ip4=msg["dst_ipv4"],\
        #      dst_host_ip4=msg["remote_host_ipv4"],\
        #      src_host_ip4=self.natswitch.host_ip,\
        #      dst_transport=msg["dst_port"])
        #elif msg["type"] == "packet_notify_remote":
        #    self.natswitch.insert_packet_translate_flow_entry(\
        #      src_mac=msg["dst_mac"], nw_proto=msg["nw_proto"],\
        #      src_ipv4=msg["dst_ipv4"], src_transport=msg["dst_port"],\
        #      src_random_tp=msg["dst_random_port"],\
        #      dst_random_tp=msg["src_random_port"],\
        #      dst_guest_ip4=msg["src_ipv4"],\
        #      dst_host_ip4=msg["local_host_ipv4"],\
        #      src_host_ip4=msg["remote_host_ipv4"],\
        #      dst_transport=msg["src_port"])
        else:
          print("unknown on_message")



class NatSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    # You can specify RYU Apps you want to use in this dictionary
    # http://ryu.readthedocs.org/en/latest/api_ref.html#ryu.base.app_manager.RyuApp._CONTEXTS
    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        super(NatSwitch, self).__init__(*args, **kwargs)
        self.wan_port = None
        self.wan_mac_port_map = []
        self.local_port = None
        self.lan_mac_port_map = {}
        self.run_once = True
        self.datapath = None
        self.dpset = kwargs['dpset']
        self.lan_ports_list = []

        # Starts IPOP Controller
        if IPOP_STARTS:
            # Kind of wanted to tincan binary itself. but failed. It is hard to start sudo command through script.
            #ipop_tincan_stdin = "sudo " + IPOP_TINCAN_BINARY_PATH + " &> tincan.log ;"
            #self.logger.info("Starting IPOP TINCAN BINARY(" + ipop_tincan_stdin + ")")
            #ipop_tincan_stdout = commands.getoutput(ipop_tincan_stdin)
            #self.logger.info("stdout:" + ipop_tincan_stdout)
            #sys.path.append(IPOP_CONTROLLER_PATH)
            import controller
            ipop = controller.IpopController(IPOP_CONFIG_COMMAND_LINE, self.logger)
            ipop.run()
            ocs = OpenflowControllerSlot(observer.Observable(), self);
            
            self.logger.setLevel(logging.DEBUG)
            _ = commands.getoutput("sudo ovs-vsctl del-port" + BRIDGE_NAME + IPOP_TAP_INTERFACE_NAME)
            self.logger.info("Removing " + IPOP_TAP_INTERFACE_NAME + " to " + BRIDGE_NAME + "\nreturning --- ".format(_))
            out = commands.getoutput("sudo ovs-vsctl add-port" + BRIDGE_NAME + IPOP_TAP_INTERFACE_NAME)
            self.logger.info("Attaching " + IPOP_TAP_INTERFACE_NAME + " to " + BRIDGE_NAME + "\nreturning --- ".format(out))


        # Retrieve IP of Gateway of Host network. 
        route_table_fd = open('/proc/net/route', 'r')
        route_table = route_table_fd.read()
        self.host_gw_ip = ip4_h2a(route_table.split("\n")[1].split("\t")[2])
        self.logger.info("My Host Gateway IP address:{0}".format(self.host_gw_ip))

        # Retrieve MAC address of Host Gateway. Looping arp table and find mac
        # address 
        arp_table_fd = open('/proc/net/arp', 'r')
        arp_table = arp_table_fd.read()
        for i in range(0, len(arp_table.split("\n"))-1):
            if arp_table.split("\n")[i].split()[0] == self.host_gw_ip:
                self.host_gw_mac = arp_table.split("\n")[i].split()[3]
        self.logger.info("My Host Gateway MAC address:{0}".format(self.host_gw_mac))

        # Create a random MAC address. This address is used for GW
        # _ = '%010x' % random.randrange(16**10)
        _ = format(random.randrange(16**10), '010x')
        self.gw_mac = "df:" + _[:2] + ":" + _[2:4] + ":" + _[4:6] + ":" +\
                              _[6:8] + ":" + _[8:10]
        self.logger.info("My Gateway MAC address:{0}".format(self.gw_mac))
        self.gw_ip = GATEWAY_IP 

        # NAT rule dictionary for ICMP (ICMP ID/port number)
        self.icmp_nat = {}

        # HOST physical NIC
        host_ip = commands.getoutput("ip address show dev "+BRIDGE_NAME).split()
        self.host_ip = host_ip[host_ip.index('inet')+1].split('/')[0]
        host_mac = commands.getoutput("ip address show dev " +\
                                      WAN_IF_NAME).split()
        self.host_mac = host_mac[host_mac.index('link/ether')+1]
        self.logger.info("My Host IP address:{0} MAC address:{1}".format(\
                         self.host_ip, self.host_mac))
        global HOST_IP
        HOST_IP = self.host_ip

        # Retrieve IPOP IPv4/IPv6 address

        # Socket interface for communicating with IPOP
        #self.oi_sock_local = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        #self.oi_sock_remote = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        #self.oi_sock_remote = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #self.oi_sock_local.bind(("::1", 30001))

        # TODO need more elaborate way to retrieve IPv6 address of ipop tap
        #_ = commands.getoutput("ip address show dev "+"ipop")
        #__ = _.split() 
        #ipop_ipv6 = None
        #for i in __:
        #    if i[0:19] == "fd50:dbc:41f2:4a3c:":
        #        ipop_ipv6 = i.split("/")[0]
        #self.oi_sock_remote.bind((ipop_ipv6, 30002))

        # TODO need more elaborate way to retrieve IPv4 address of ipop tap
        # Don't need this part. We move to inherent API for ICC. Thus not creating socket
        #_ = commands.getoutput("ip address show dev "+"ipop")
        #__ = _.split() 
        #___ =  __.index("inet")
        #print ___ 
        #ipop_ipv4 = __[___ +1].split("/")[0]
        #print ipop_ipv4
        #self.oi_sock_remote.bind((ipop_ipv4, 30002))

        #t = threading.Thread(target=self.run_oi_server)
        #t.daemon = True
        #t.start()


    # Since new ICC is added. This part is not necessary.
    #def run_oi_server(self):
    #    while True:
    #        socks, _, _ = select.select([self.oi_sock_local, self.oi_sock_remote], [], [], 30)
    #        for sock in socks:
    #            data, addr = sock.recvfrom(2048)
    #            msg = json.loads(data)
    #            self.logger.info("Message from socket {0} {1}".format(addr, msg))
    #            if msg["type"] == "packet_notify" and sock == self.oi_sock_local:
    #                # TODO Port number should be assigned dynamically 
    #                self.insert_packet_translate_flow_entry(
    #                  src_mac=msg["src_mac"], nw_proto=msg["nw_proto"],\
    #                  src_ipv4=msg["src_ipv4"], src_transport=msg["src_port"],\
    #                  src_random_tp=msg["src_random_port"],\
    #                  dst_random_tp=msg["dst_random_port"],\
    #                  dst_guest_ip4=msg["dst_ipv4"],\
    #                  dst_host_ip4=msg["remote_host_ipv4"],\
    #                  dst_transport=msg["dst_port"])
    #            elif msg["type"] == "packet_notify" and sock == self.oi_sock_remote:
    #                self.insert_packet_translate_flow_entry(
    #                  src_mac=msg["dst_mac"], nw_proto=msg["nw_proto"],\
    #                  src_ipv4=msg["dst_ipv4"], src_transport=msg["dst_port"],\
    #                  src_random_tp=msg["dst_random_port"],\
    #                  dst_random_tp=msg["src_random_port"],\
    #                  dst_guest_ip4=msg["src_ipv4"],\
    #                  dst_host_ip4=self.host_ip,\
    #                  dst_transport=msg["src_port"])
    #            else:
    #                self.logger.info("This shouldn't happen")

    def insert_guest_to_host_flow(self, src_guest_ip4, dst_guest_ip4, nw_proto, src_guest_tp, dst_guest_tp, dst_host_ip4, src_host_ip4, src_host_tp, dst_host_tp):
        match = self.datapath.ofproto_parser.OFPMatch(dl_type=0x0800,\
           nw_src=ip4_a2i(src_guest_ip4), nw_dst=ip4_a2i(dst_guest_ip4),\
           nw_proto=nw_proto, tp_src=src_guest_tp, tp_dst=dst_guest_tp)

        if self.datapath == None:
            return
        ofproto = self.datapath.ofproto

        actions = []
        actions.append(self.datapath.ofproto_parser.OFPActionSetDlSrc(\
                       mac_a2b(self.host_mac)))
        # TODO should i specific about destination mac address when it comes to amazon
        actions.append(self.datapath.ofproto_parser.OFPActionSetDlDst(\
                       mac_a2b(self.host_gw_mac)))
        actions.append(self.datapath.ofproto_parser.OFPActionSetNwSrc(\
                       ip4_a2i(src_host_ip4)))
        actions.append(self.datapath.ofproto_parser.OFPActionSetNwDst(\
                       ip4_a2i(dst_host_ip4)))
        actions.append(self.datapath.ofproto_parser.OFPActionSetTpSrc(\
                      src_host_tp))
        actions.append(self.datapath.ofproto_parser.OFPActionSetTpDst(\
                       dst_host_tp))
        actions.append(self.datapath.ofproto_parser.OFPActionOutput(\
                       self.wan_port))

        mod = self.datapath.ofproto_parser.OFPFlowMod(datapath=self.datapath,\
            match=match, cookie=0, command=ofproto.OFPFC_ADD,\
            idle_timeout=0, hard_timeout=0,\
            priority=ofproto.OFP_DEFAULT_PRIORITY+2,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        self.datapath.send_msg(mod)

    def insert_host_to_guest_flow(self, src_host_ip4, dst_host_ip4, nw_proto, src_host_tp, dst_host_tp, src_guest_tp, dst_guest_tp, dst_mac, src_guest_ip4, dst_guest_ip4):
        match = self.datapath.ofproto_parser.OFPMatch(dl_type=0x0800,\
           nw_src=ip4_a2i(src_host_ip4), nw_dst=ip4_a2i(dst_host_ip4),\
           nw_proto=nw_proto, tp_src=src_host_tp, tp_dst=dst_host_tp)

        if self.datapath == None:
            return
        ofproto = self.datapath.ofproto

        actions = []
        actions.append(self.datapath.ofproto_parser.OFPActionSetDlSrc(\
                         mac_a2b(self.gw_mac)))
        actions.append(self.datapath.ofproto_parser.OFPActionSetDlDst(\
                           mac_a2b(dst_mac)))
        actions.append(self.datapath.ofproto_parser.OFPActionSetNwSrc(\
                         ip4_a2i(src_guest_ip4)))
        actions.append(self.datapath.ofproto_parser.OFPActionSetNwDst(\
                           ip4_a2i(dst_guest_ip4)))
        actions.append(self.datapath.ofproto_parser.OFPActionSetTpSrc(\
                           src_guest_tp))
        actions.append(self.datapath.ofproto_parser.OFPActionSetTpDst(\
                          dst_guest_tp))
        #actions.append(self.datapath.ofproto_parser.OFPActionOutput(\
        #                    ofproto.OFPP_LOCAL))
        actions.append(self.datapath.ofproto_parser.OFPActionOutput(\
              self.lan_mac_port_map[self.datapath.id][dst_mac.lower()]))

        mod = self.datapath.ofproto_parser.OFPFlowMod(datapath=self.datapath,\
            match=match, cookie=0, command=ofproto.OFPFC_ADD,\
            idle_timeout=0, hard_timeout=0,\
            priority=ofproto.OFP_DEFAULT_PRIORITY+2,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        self.datapath.send_msg(mod)


    def insert_packet_translate_flow_entry(self, src_mac, nw_proto, src_ipv4,\
      src_transport, src_random_tp, dst_random_tp, dst_guest_ip4, dst_host_ip4,\
      src_host_ip4, dst_transport):

        self.logger.info("insert_packet_translate_flow_entry nw_proto:{0}"
          " src_mac:{1}, src_ipv4:{2}, src_transport:{3}, src_random_tp:{4},"
          " dst_random_tp:{5}, dst_guest_ip4:{6}, dst_host_ip4:{7}"
          " dst_transport:{8}".format(nw_proto, src_mac, src_ipv4,\
          src_transport, src_random_tp, dst_random_tp, dst_guest_ip4,\
          dst_host_ip4, dst_transport))

        if self.datapath == None:
            return
        ofproto = self.datapath.ofproto
        in_match = self.datapath.ofproto_parser.OFPMatch(dl_type=0x0800,\
           nw_src=ip4_a2i(src_ipv4), nw_dst=ip4_a2i(dst_guest_ip4),\
           nw_proto=nw_proto, tp_src=src_transport, tp_dst=dst_transport)

        in_actions = []
        in_actions.append(self.datapath.ofproto_parser.OFPActionSetDlSrc(\
                          mac_a2b(self.host_mac)))
        #in_actions.append(self.datapath.ofproto_parser.OFPActionSetDlDst(\
        #                  mac_a2b(self.host_gw_mac)))
        in_actions.append(self.datapath.ofproto_parser.OFPActionSetNwSrc(\
                          ip4_a2i(self.host_ip)))
        in_actions.append(self.datapath.ofproto_parser.OFPActionSetNwDst(\
                          ip4_a2i(dst_host_ip4)))
        in_actions.append(self.datapath.ofproto_parser.OFPActionSetTpSrc(\
                         src_random_tp))
        in_actions.append(self.datapath.ofproto_parser.OFPActionSetTpDst(\
                          dst_random_tp))
        in_actions.append(self.datapath.ofproto_parser.OFPActionOutput(\
                          self.wan_port))

        in_mod = self.datapath.ofproto_parser.OFPFlowMod(\
            datapath=self.datapath, match=in_match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY+2,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=in_actions)
        self.datapath.send_msg(in_mod)

        out_match = self.datapath.ofproto_parser.OFPMatch(dl_type=0x0800,\
           nw_src=ip4_a2i(dst_host_ip4), nw_dst=ip4_a2i(src_host_ip4),\
           nw_proto=nw_proto, tp_src=dst_random_tp, tp_dst=src_random_tp)

        out_actions = []
        out_actions.append(self.datapath.ofproto_parser.OFPActionSetDlSrc(\
                           mac_a2b(self.gw_mac)))
        out_actions.append(self.datapath.ofproto_parser.OFPActionSetDlDst(\
                           mac_a2b(src_mac)))
        out_actions.append(self.datapath.ofproto_parser.OFPActionSetNwSrc(\
                           ip4_a2i(dst_guest_ip4)))
        out_actions.append(self.datapath.ofproto_parser.OFPActionSetNwDst(\
                           ip4_a2i(src_ipv4)))
        out_actions.append(self.datapath.ofproto_parser.OFPActionSetTpSrc(\
                           dst_transport))
        out_actions.append(self.datapath.ofproto_parser.OFPActionSetTpDst(\
                           src_transport))
        #out_actions.append(self.datapath.ofproto_parser.OFPActionOutput(\
        #                   ))
        out_actions.append(self.datapath.ofproto_parser.OFPActionOutput(\
              self.lan_mac_port_map[self.datapath.id][src_mac.lower()]))
                            #ofproto.OFPP_LOCAL))


        out_mod = self.datapath.ofproto_parser.OFPFlowMod(datapath=self.datapath,\
          match=out_match, cookie=0, command=ofproto.OFPFC_ADD, idle_timeout=0,\
          hard_timeout=0, priority=ofproto.OFP_DEFAULT_PRIORITY+2,\
          flags=ofproto.OFPFF_SEND_FLOW_REM, actions=out_actions)

        self.datapath.send_msg(out_mod)

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_msg(mod)

    def add_flow2(self, datapath, in_port, src, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_src = haddr_to_bin(src), dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_msg(mod)

    def update_ports(self, datapath):
        ports_list = self.dpset.get_ports(datapath.id)
        self.logger.info("Port lists {0}".format(ports_list))
        for i in ports_list:
            if i.name == WAN_IF_NAME:
                self.wan_port = i.port_no
            elif i.name == BRIDGE_NAME:
                self.local_port = i.port_no
            else:
                self.lan_ports_list.append(i.port_no)

    # This event is called after FEATURES_REPLY
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _whatever(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto

        self.update_ports(datapath)

        # Forward all ICMP message to controller
        # It is necessary because we cannot make NAT rule with openflow rule
        match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_proto=1)

        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        mod = datapath.ofproto_parser.OFPFlowMod(datapath=ev.msg.datapath,
                match=match, cookie=0, command=ofproto.OFPFC_ADD,
                idle_timeout=0, hard_timeout=0, 
                priority=ofproto.OFP_DEFAULT_PRIORITY+2, 
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_msg(mod)

        if self.wan_port == None:
            self.logger.info("Cannot find WAN interface : {0}".format(self.wan_port))
            sys.exit()

    # I should capture the error message from the switch
    @set_ev_cls(ofp_event.EventOFPErrorMsg, CONFIG_DISPATCHER)
    def _whatsoever(self, ev):
        print "error event"
 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath
        self.datapath = msg.datapath
        ofproto = datapath.ofproto

        # It's really nice that RYU has ample of packet parsing APIs
        # https://github.com/osrg/ryu/tree/master/ryu/lib/packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ipv4_pk = pkt.get_protocol(ipv4.ipv4)
        tcp_pk = pkt.get_protocol(tcp.tcp)
        udp_pk = pkt.get_protocol(udp.udp)

        dst = eth.dst
        src = eth.src

        from_wan = False
        dpid = datapath.id
        self.lan_mac_port_map.setdefault(dpid, {})

        # Ignore Cisco discovery protocol
        if dst[:17] == "01:00:0c:cc:cc:cc":
            self.logger.info("Ignore Cisco discovery protocol")
            return
       
        # Ignore Spanning Tree Protocol
        if dst[:8] == "01:80:c2":
            self.logger.info("Ignore Spanning Tree Protocol")
            return

        # Ignore ethertype 0x9000(Ethernet Configuration Testing Protocol)
        if eth.ethertype == 36864:
            self.logger.info("Ignore Ethernet Configuration Testing Protocol")
            return

        # Ignores multicast MAC
        if dst[:8] == "01:00:5e":
            self.logger.info("Ignore Multicast MAC address")
            return

        self.logger.info("packet in dpid:%s src:%s dst:%s ethtype:%s, msg:%s",\
          dpid, src, dst, eth.ethertype, msg)
        
 
        # We handle ALL ICMP reply packet here (with ICMP NATTING)
        if eth.ethertype == 2048 and msg.data[23] == "\x01" and msg.data[34] == "\x00":
            print "ICMP reply message"
            out_port = self.icmp_nat[msg.data[38:40]]["in_port"]
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            if out_port == self.wan_port:
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                        buffer_id=msg.buffer_id, in_port=msg.in_port,
                        actions=actions, data=data)
            else:
                new_data = ""
                new_data += mac_a2b(self.icmp_nat[msg.data[38:40]]["mac"])
                new_data += mac_a2b(self.gw_mac)
                new_data += data[12:24]
                new_data += checksum(data[14:24] + data[26:30] +\
                            ip4_a2b(self.icmp_nat[msg.data[38:40]]["ipv4"]))
                new_data += data[26:30] # Change source IP to gateway
                new_data += ip4_a2b(self.icmp_nat[msg.data[38:40]]["ipv4"]) # Padd the rest of the ping message
                new_data += data[34:]
         
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                    actions=actions, data=new_data)

            datapath.send_msg(out)
            self.logger.info("Sending ICMP packet(ID:{0}) to {1}".format(msg.data[38:40], out_port))

            return

        # This packet comes from the WAN port
        if msg.in_port == self.wan_port:
            # If it's ARP, just ignores. (NOt correct implementation)
            # TODO host should replya with proper ARP reply
            #if eth.ethertype == 2054:
            #    return;

            if not src in self.wan_mac_port_map:
                self.wan_mac_port_map.append(src)
            print "packet comes from the WAN"
            print self.wan_mac_port_map
            
            actions = []
            actions.append(datapath.ofproto_parser.OFPActionOutput(self.local_port))
            self.add_flow2(datapath, msg.in_port, src, dst, actions)



        # This packet comes from the HOST
        elif msg.in_port == ofproto.OFPP_LOCAL:
            # Ping(request) message come from LOCAL bridge interface
            if eth.ethertype == 2048 and msg.data[23] == "\x01" and msg.data[34] == "\x08":
                self.icmp_nat[msg.data[38:40]] = {"in_port":msg.in_port,\
                  "ipv4":ip4_b2a(msg.data[26:30]), "mac":mac_b2a(msg.data[6:12])}
                self.logger.info("ICMP NAT rule is added %s", self.icmp_nat)
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                actions = [datapath.ofproto_parser.OFPActionOutput(self.wan_port)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                    actions=actions, data=data)
                datapath.send_msg(out)
                return

            # The destination address simply not mapped to port yet
            actions = []
            actions.append(datapath.ofproto_parser.OFPActionOutput(self.wan_port))
            print "packet comes from local"
            print self.wan_mac_port_map
            if dst in self.wan_mac_port_map:
                # Add flow to openflow switch to avoid additional ofp_packet_in
                self.add_flow(datapath, msg.in_port, dst, actions)


        # the packet is from LAN PORTS
        else:

            # This is ARP message inquring gateway
            # ARP 0x0806(2054)
            # OP 01 (request)
            if eth.ethertype == 2054 and msg.data[20:22] == "\x00\x01" and\
               ip4_b2a(msg.data[38:]) == self.gw_ip: # Target IPv4 match with my gateway IPv4
 
                # Now create ARP reply message
                arp_reply = ""
                arp_reply += msg.data[6:12] # Destination MAC
                arp_reply += mac_a2b(self.gw_mac) # Source MAC (Gateway MAC)
                arp_reply += "\x08\x06" #Ether type of ARP
                arp_reply += "\x00\x01" #Hardware Type
                arp_reply += "\x08\x00" #Protocol Type
                arp_reply += "\x06" #Hardware address length
                arp_reply += "\x04" #Protocol address length
                arp_reply += "\x00" #Operation (ARP reply)
                arp_reply += "\x02" #Operation (ARP reply)
                arp_reply += mac_a2b(self.gw_mac) # Sender hardware address (MAC)
                arp_reply += ip4_a2b(self.gw_ip)  # Sender protocol address (IPv4)
                arp_reply += msg.data[6:12]  # Target hardware address (MAC)
                arp_reply += msg.data[28:32] # Target protocol address (IPv4)
                arp_reply += "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

                self.logger.info("arp_reply %s", str(arp_reply.encode("hex")))
                self.dpset.get_ports(dpid)
 
                # Send ARP reply to port where ARP request from
                actions = [datapath.ofproto_parser.OFPActionOutput(msg.in_port)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_LOCAL,
                    actions=actions, data=arp_reply)
                datapath.send_msg(out)

                # No flow mapping is necessary
                return

            print self.lan_mac_port_map[dpid]
            # Ping(request) message come from LAN virtual interface to LAN
            if eth.ethertype == 2048 and msg.data[23] == "\x01"\
               and (msg.data[34] == "\x08" or msg.data[34] == "\x00")\
               and dst in self.lan_mac_port_map[dpid]:
                self.icmp_nat[msg.data[38:40]] = {"in_port":msg.in_port,\
                  "ipv4":ip4_b2a(msg.data[26:30]), "mac":mac_b2a(msg.data[6:12])}
                print "Ping request message destined to LAN"
                print self.lan_mac_port_map[dpid]
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                actions = [datapath.ofproto_parser.OFPActionOutput(self.lan_mac_port_map[dpid][dst])]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                    actions=actions, data=data)
                datapath.send_msg(out)
                return

            # Ping(request) message come from LAN virtual interface to WAN
            if eth.ethertype == 2048 and msg.data[23] == "\x01" and msg.data[34] == "\x08":
                self.icmp_nat[msg.data[38:40]] = {"in_port":msg.in_port,\
                  "ipv4":ip4_b2a(msg.data[26:30]), "mac":mac_b2a(msg.data[6:12])}
                self.logger.info("ICMP NAT rule is added %s", self.icmp_nat)
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                # TODO WE assume the host physical interface is at port 1
                #actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
                actions = [datapath.ofproto_parser.OFPActionOutput(self.wan_port)]

                # Update packet data
                new_data = ""
                new_data += mac_a2b(self.host_gw_mac) # Destination MAC
                #new_data += mac_a2b("e8:11:32:67:0a:43") # Destination MAC
                new_data += mac_a2b(self.host_mac) # Source MAC
                new_data += data[12:24]
                new_data += checksum(data[14:24] + ip4_a2b(self.host_ip) + data[30:34])
                new_data += ip4_a2b(self.host_ip) # Change source IP to gateway
                new_data += data[30:] # Padd the rest of the ping message

                # Update MAC address and IP address of ICMP packet to host interface
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                    actions=actions, data=new_data)
                datapath.send_msg(out)
             
                return

            # This message is ICMP Ping request message querying to gateway 
            # TODO not implemented. GW does not have to reply to PING
            if eth.ethertype == 2048 and ip4_b2a(msg.data[30:34]) == self.gw_ip\
               and msg.data[34] == "\x08": # Target IPv4 match with my gateway IPv4

                ping_reply = ""
                ping_reply += msg.data[6:12]
                ping_reply += mac_a2b(self.gw_mac) # Source MAC (Gateway MAC)
                ping_reply += "\x08\x00" #Ether type of ARP
                ping_reply += "\x45" # Protocol version and header length
                ping_reply += "\x00" # Differentiated field
                ping_reply += msg.data[15:17] # Length of IP packet
                ping_reply += chr(random.randint(0,255)) +\
                  chr(random.randint(0,255)) # I assume identifcation can be 
                                             # any value
                ping_reply += "\x40" # Flags (Don't fragment) 
                ping_reply += "\x00" # Fragment offset
                ping_reply += "\x40" # TTL
                ping_reply += "\x01" # ICMP protocol

                return

            # This is TCP/UDP packet coming from the LAN ports to public
            # internet
            if eth.ethertype == 2048 and (msg.data[23] == "\x06" or\
               msg.data[23] == "\x11") and\
               not is_in_subnet(self.gw_ip, ipv4_pk.dst,LAN_SUBNET_RANGE):

                if tcp_pk:
                    src_port = tcp_pk.src_port
                    dst_port = tcp_pk.dst_port
                elif udp_pk:
                    src_port = udp_pk.src_port
                    dst_port = udp_pk.dst_port
                
                # Ignores DHCP message
                if src_port == 68 and dst_port == 67:
                    return

                # NAT outgoing packet flow rule
                in_match = datapath.ofproto_parser.OFPMatch(\
                  in_port=msg.in_port, dl_type=0x0800,\
                  nw_src=ip4_a2i(ipv4_pk.src), nw_dst=ip4_a2i(ipv4_pk.dst),\
                  nw_proto=ipv4_pk.proto, tp_src=src_port, tp_dst=dst_port)

                in_actions = []
                in_actions.append(datapath.ofproto_parser.OFPActionSetDlSrc(\
                                  mac_a2b(self.host_mac)))
                in_actions.append(datapath.ofproto_parser.OFPActionSetDlDst(\
                                  mac_a2b(self.host_gw_mac)))
                in_actions.append(datapath.ofproto_parser.OFPActionSetNwSrc(\
                                  ip4_a2i(self.host_ip)))
                in_actions.append(datapath.ofproto_parser.OFPActionOutput(1))

                in_mod = datapath.ofproto_parser.OFPFlowMod( datapath=datapath,\
                  match=in_match, cookie=0, command=ofproto.OFPFC_ADD,\
                  idle_timeout=0, hard_timeout=0,\
                  priority=ofproto.OFP_DEFAULT_PRIORITY+2,\
                  flags=ofproto.OFPFF_SEND_FLOW_REM, actions=in_actions)

                datapath.send_msg(in_mod)

                # NAT incoming packet flow rule
                out_match = datapath.ofproto_parser.OFPMatch(\
                  in_port=1, dl_type=0x0800, nw_src=ip4_a2i(ipv4_pk.dst),\
                  nw_dst=ip4_a2i(self.host_ip), nw_proto=ipv4_pk.proto,\
                  tp_src=dst_port, tp_dst=src_port)

                out_actions = []
                out_actions.append(datapath.ofproto_parser.OFPActionSetDlSrc(\
                                  mac_a2b(self.gw_mac)))
                out_actions.append(datapath.ofproto_parser.OFPActionSetDlDst(\
                                  mac_a2b(eth.src)))
                out_actions.append(datapath.ofproto_parser.OFPActionSetNwDst(\
                                  ip4_a2i(ipv4_pk.src)))
                out_actions.append(datapath.ofproto_parser.OFPActionOutput(\
                                  msg.in_port))

                out_mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,\
                  match=out_match, cookie=0, command=ofproto.OFPFC_ADD,\
                  idle_timeout=0, hard_timeout=0,\
                  priority=ofproto.OFP_DEFAULT_PRIORITY+2,\
                  flags=ofproto.OFPFF_SEND_FLOW_REM, actions=out_actions)

                datapath.send_msg(out_mod)

                # Use actions for outgoing packet rule of NAT
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                    actions=in_actions, data=data)
                datapath.send_msg(out)

                return

            # MAC destination is in the same virtual network layer
            if dst in self.lan_mac_port_map[dpid]:
                out_port = self.lan_mac_port_map[dpid][dst]
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, msg.in_port, dst, actions)
    
            # The destination address simply not mapped to port yet
            else:
                # Flood packets to virtual ports 
                print "No flow table ... thus flooding to LAN ports"
                print self.lan_ports_list
                actions = []
                for i in self.lan_ports_list:
                    actions.append(datapath.ofproto_parser.OFPActionOutput(i))
                actions.append(datapath.ofproto_parser.OFPActionOutput(\
                              ofproto.OFPP_LOCAL))

            # UPdate MAC-port table
            print "updateing LAN MAC PORT table"
            self.lan_mac_port_map[dpid][src] = msg.in_port

        # install a flow to avoid packet_in next time
        # If actions are specified then mapping
        #if actions:
        #    self.add_flow(datapath, msg.in_port, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
                 
    # This event is called after ports status change
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
        self.update_ports(ev.msg.datapath)


