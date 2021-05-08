# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

## command to bulid
# sudo mn --controller=remote,ip=127.0.0.1 --topo tree,depth=4 --switch default,protocols=OpenFlow13 --mac --arp

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mapping = {}
        self.data = [{9, 12, 15, 3, 6}, {10, 13, 16, 4, 1, 7}, {11, 14, 2, 5, 8}]
        self.leaf = {4, 5, 7, 8, 11, 12, 14, 15}
        self.leaf_port_map = {} # {number:list of number}
        self.set_tenant()

    def set_tenant(self):
        
        for i in range(3):
            for j in self.data[i]:
                self.mapping[j] = i
        
        list_leaf = list(self.leaf)
        for i in range(len(list_leaf)):
            self.leaf_port_map[list_leaf[i]] = [i*2 +1, i*2 +2]
        
        # for i in self.leaf:
        #     self.logger.info("%d", i)
        #     self.logger.info("%d, %d", self.leaf_port_map[i][0], self.leaf_port_map[i][1])

    # in period of handshake
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def detect_tenant(self, dst, src):
        # broadcast
        if src.find("00:00:00:00:00") != -1 and dst.find("ff:ff:ff:ff:ff:ff") != -1:
            return 2

        # deal switch packet
        if dst.find("00:00:00:00:00") == -1:
            return 0
        # use self.mapping to search which self.data
        dst = int( dst[dst.rfind(':') + 1 : ], 16)
        # dst = dst[dst.rfind(':') + 1 : ] 
        src = int( src[src.rfind(':') + 1 : ], 16 )
        if dst in self.data[self.mapping[src]]:
            return 0
        else:
            return 1


    def normal_operation(self, msg, datapath, ofproto, parser, in_port, pkt, eth, dst, src, dpid):
        # check in mac address or not
        # in set out_port to correct port, not in set out_port to flooding
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        # if not flooding insert flow entries to switch
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def additional_operation(self, msg, datapath, ofproto, parser, in_port, pkt, eth, dst, src, dpid):

        # drop packet action
        # actions = [parser.OFPActionOutput(out_port)]
        actions = []

        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        # add flow to drop packet
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 2, match, actions, msg.buffer_id)
            return
        else:
            self.add_flow(datapath, 2, match, actions)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def broadcast_operation(self, msg, datapath, ofproto, parser, in_port, pkt, eth, dst, src, dpid):
        # 4 5 7 8 11 12 14 15 self.leaf set() and self.leaf_port_map {}
        # if not leaf switch we don't care
        # self.logger.info("in broadcast")
        # print("in broadcast\n")
        if dpid not in self.leaf:
            self.normal_operation(msg, datapath, ofproto, parser, in_port, pkt, eth, dst, src, dpid)
            return
        # change src mac to number
        src_t = int( src[src.rfind(':') + 1 : ], 16 )
        # self.logger.info("src_t %d %d %d", src_t, self.leaf_port_map[dpid][0], self.leaf_port_map[dpid][1])
        # in src leaf switch
        if src_t == self.leaf_port_map[dpid][0] or src_t == self.leaf_port_map[dpid][1]:
            # self.logger.info("normal")
            self.normal_operation(msg, datapath, ofproto, parser, in_port, pkt, eth, dst, src, dpid)
            return
        
        # change src mac to number
        src = int( src[src.rfind(':') + 1 : ], 16 )
        data = None
        for i in range ( len(self.leaf_port_map[dpid]) ):
            # if in same tanant transmit and return
            # self.logger.info("dpid %d", dpid)
            if self.leaf_port_map[dpid][i] in self.data[self.mapping[src]]:
                # self.logger.info("find match")
                actions = [parser.OFPActionOutput( i+1 )]
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return

        # not match drop
        actions = []
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
    # in period of packet_in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # import pdb
        # pdb.set_trace()

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        flow_type = self.detect_tenant(dst, src)

        # self.logger.info(flow_type)
        
        if flow_type == 1:  # peer to peer
            self.additional_operation(msg, datapath, ofproto, parser, in_port, pkt, eth, dst, src, dpid)
        elif flow_type == 2:    # broadcast
            self.broadcast_operation(msg, datapath, ofproto, parser, in_port, pkt, eth, dst, src, dpid)
        else:   # other
            self.normal_operation(msg, datapath, ofproto, parser, in_port, pkt, eth, dst, src, dpid)

















        # # learn a mac address to avoid FLOOD next time.
        # self.mac_to_port[dpid][src] = in_port

        # # check in mac address or not
        # # in set out_port to correct port, not in set out_port to flooding
        # if dst in self.mac_to_port[dpid]:
        #     out_port = self.mac_to_port[dpid][dst]
        # else:
        #     out_port = ofproto.OFPP_FLOOD

        # actions = [parser.OFPActionOutput(out_port)]

        # # install a flow to avoid packet_in next time
        # # if not flooding insert flow entries to switch
        # if out_port != ofproto.OFPP_FLOOD:
        #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        #     # verify if we have a valid buffer_id, if yes avoid to send both
        #     # flow_mod & packet_out
        #     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
        #         self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        #         return
        #     else:
        #         self.add_flow(datapath, 1, match, actions)
        # data = None
        # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #     data = msg.data

        # out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                           in_port=in_port, actions=actions, data=data)
        # datapath.send_msg(out)
