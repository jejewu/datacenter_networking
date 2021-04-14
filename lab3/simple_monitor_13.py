# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub


class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(3)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # req = parser.OFPFlowStatsRequest(datapath)
        # datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        # req = parser.OFPPortDescStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        # datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)




    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        # self.logger.info('datapath         port     '
        #                  'rx-pkts  rx-bytes rx-error '
        #                  'tx-pkts  tx-bytes tx-error')
        # self.logger.info('---------------- -------- '
        #                  '-------- -------- -------- '
        #                  '-------- -------- --------')
        self.logger.info('***************************')
        
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.logger.info('Switch ID: %d',dpid)

        self.logger.info('Port No  Tx-Bytes Rx-Bytes')
        self.logger.info('-------- -------- -------- ')
        for stat in sorted(body, key=attrgetter('port_no')):
            # self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
            #                  ev.msg.datapath.id, stat.port_no,
            #                  stat.rx_packets, stat.rx_bytes, stat.rx_errors,
            #                  stat.tx_packets, stat.tx_bytes, stat.tx_errors)
            self.logger.info('%8x %8d %8d',
                             stat.port_no,
                             stat.tx_bytes, stat.rx_bytes)

        # for i in self.mac_to_port.keys():
        #     self.logger.info('switch %s            ', i)
        #     for j in self.mac_to_port[i].keys():
        #         self.logger.info('%s %8x', j, self.mac_to_port[i][j])
        self.logger.info('         ')
        self.logger.info('MAC Address Table   Port No')
        self.logger.info('----------------------------')
        # self.logger.info('switch %d   ',dpid)
        # self.logger.info(%s, typeof(self.mac_to_port[dpid]))
        try:
            for mac_address in self.mac_to_port[dpid].keys():
                port = self.mac_to_port[dpid][mac_address]
                self.logger.info('%s  %8x', mac_address, port)
        except KeyError:
            a = 3 
        self.logger.info('***************************')
        self.logger.info('                           ')





    # @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    # def port_desc_stats_reply_handler(self, ev):
    #     ports = []
    #     self.logger.info('----------------------------')
    #     self.logger.info('MAC Address Table   Port No')

    #     for p in ev.msg.body:
    #         # ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
    #         #             'state=0x%08x curr=0x%08x advertised=0x%08x '
    #         #             'supported=0x%08x peer=0x%08x curr_speed=%d '
    #         #             'max_speed=%d' %
    #         #             (p.port_no, p.hw_addr,
    #         #             p.name, p.config,
    #         #             p.state, p.curr, p.advertised,
    #         #             p.supported, p.peer, p.curr_speed,
    #         #             p.max_speed))
    #         self.logger.info('%s  %8x', p.hw_addr, p.port_no)

    #     self.logger.info('***************************')
    #     self.logger.info('                           ')
    #     self.logger.debug('OFPPortDescStatsReply received: %s', ports)
