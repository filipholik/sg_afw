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

# Adaptive Firewall for Smart Grid Security, v3.0.2

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from file_loader import FileLoader
from ryu.ofproto import inet
from ryu.lib.packet import ipv4
from ryu.lib.packet import vlan

from ryu.ofproto.ofproto_v1_2 import OFPG_ANY

import time
import json
import logging
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib


sg_controller_instance_name = 'sg_controller_api_app'
url = '/fw/rules/{dpid}'
url2 = '/fw/traffic/{dpid}'

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = { 'wsgi' : WSGIApplication }
    flow_rules = 0
    traffic = []
    datapath_ids = []
    flow_reply_received = 0


    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        wsgi = kwargs['wsgi']
        wsgi.register(SGController, {sg_controller_instance_name : self})


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapath_ids.append(datapath)
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
        action_normal = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        action_copy = [parser.OFPActionOutput(ofproto.OFPP_NORMAL), parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        #TODO set idle_timeouts to 0 - infinity, 180 only for testing purposes


        #LLDP frames
        self.add_flow(datapath, 1, 180, 100, parser.OFPMatch(eth_type=0x88cc), actions)

        #Hybrid SDN Config -----------------------------------------
        #BDDP frames
        self.add_flow(datapath, 1, 180, 100, parser.OFPMatch(eth_type=0x8999), actions)

        #ARP frames
        #self.add_flow(datapath, 1, 180, 100, parser.OFPMatch(eth_type=2054), action_normal)
        # first instruction to table 200 must be set
        instruction_200 = [parser.OFPInstructionGotoTable(200)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath, table_id=100, command=ofproto.OFPFC_ADD, idle_timeout = 180,
                                priority = 0, match=parser.OFPMatch(eth_type=2054), instructions=instruction_200)
        datapath.send_msg(mod)
        # rule itself must be inserted in table 200 (supports copying of packets)
        self.add_flow(datapath, 1, 180, 200, parser.OFPMatch(eth_type=2054), action_copy)

        #Deny everything else - send it to the controller
        self.add_flow(datapath, 0, 180, 100, match, actions)

        self.fw_init(datapath)


    def fw_init(self, datapath):
       parser = datapath.ofproto_parser
       ofproto = datapath.ofproto
       self.logger.info("FW Initialization started... ")
       fileLoader = FileLoader()
       rules = fileLoader.get_rules_mac()

       self.logger.info("Adding %s rules... ", len(rules))
       for rule in rules:
          #L2 rules only
          if rule.l3_proto == 0:
             self.logger.info("Adding flow: %s -> %s, L2 proto: %s",
                rule.src, rule.dst, rule.l2_proto)
             match = parser.OFPMatch(eth_dst = rule.dst, eth_src = rule.src,
                eth_type = int(rule.l2_proto, 16))
          #L3 protocol defined, but no IP addresses
          elif rule.ipv4_src == 0:
             self.logger.info("Adding flow: %s -> %s, L2 proto: %s, L3 proto: %s",
                rule.src, rule.dst, rule.l2_proto, rule.l3_proto)
             match = parser.OFPMatch(eth_dst = rule.dst, eth_src = rule.src,
                eth_type = int(rule.l2_proto, 16), ip_proto = int(rule.l3_proto))
          #L3 protocol + IP addresses
          elif rule.l3_proto != 6 and rule.l3_proto != 17 :
             self.logger.info(
                "Adding flow: %s -> %s, L2 proto: %s, L3 proto: %s, %s -> %s",
                rule.src, rule.dst, rule.l2_proto, rule.l3_proto,
                rule.ipv4_src, rule.ipv4_dst)
             match = parser.OFPMatch(eth_dst = rule.dst, eth_src = rule.src,
                eth_type = int(rule.l2_proto, 16), ip_proto = int(rule.l3_proto),
                ipv4_src = rule.ipv4_src, ipv4_dst = rule.ipv4_dst)
          #L4 ports
          else:
            l4_proto = ""
            l4_src = 0
            l4_dst = 0
            if rule.tcp_source != 0:
              l4_proto = "TCP"
              l4_src = rule.tcp_source
              l4_dst = rule.tcp_destination
            else:
              l4_proto = "UDP"
              l4_src = udp_source
              l4_dst = udp_destination

            self.logger.info(
                "Adding flow: %s -> %s, L2 proto: %s, L3 proto: %s, %s -> %s, %s: %s -> %s",
                rule.src, rule.dst, rule.l2_proto, rule.l3_proto,
                rule.ipv4_src, rule.ipv4_dst, l4_proto, l4_src, l4_dst)
            if l4_proto == "TCP":
              match = parser.OFPMatch(eth_dst = rule.dst, eth_src = rule.src,
                eth_type = int(rule.l2_proto, 16), ip_proto = int(rule.l3_proto),
                ipv4_src = rule.ipv4_src, ipv4_dst = rule.ipv4_dst,
                tcp_src = int(rule.tcp_source), tcp_dst = int(rule.tcp_destination))
            if l4_proto == "UDP":
              match = parser.OFPMatch(eth_dst = rule.dst, eth_src = rule.src,
                eth_type = int(rule.l2_proto, 16), ip_proto = int(rule.l3_proto),
                ipv4_src = rule.ipv4_src, ipv4_dst = rule.ipv4_dst,
                udp_src = int(rule.udp_source), udp_dst = int(rule.udp_destination))

          self.add_flow(datapath, 3, 120, 100, match,
             [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])


    def add_flow(self, datapath, priority, idle_timeout, table_id, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout, instructions=inst, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=idle_timeout, instructions=inst,
                                    table_id=table_id)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
      self.logger.info("F: OFPPortStatus Message Received! ")
      msg = ev.msg
      datapath = msg.datapath
      port = ev.msg.desc
      number = port.port_no
      reason = ev.msg.reason
      if port.state == 2:
         link_blocked_flg = 1
      else:
         link_blocked_flg = 0
      self.logger.info("F: Port: %s, reason: %s, blocked: %s, datapath: %s", number,reason,link_blocked_flg, datapath)
      if link_blocked_flg:
         self.logger.info("F: Link blocked. ")
      else:
         self.logger.info("F: Link not blocked. ")


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
        eth_vlan = pkt.get_protocols(vlan.vlan)[0]
        self.logger.info("F: protocol: %s, %s", eth, eth_vlan)
        #test = packet.Packet(array.array('B', ev.msg.data))
        #for p in test.protocols:
        #   self.logger.info("Protocols: %s", p)

        allow_traffic = 0
        allow_reason = ""
        if eth.ethertype == ether_types.ETH_TYPE_8021Q:
           #self.logger.info("F: Received 802.1Q frame!")
           if eth_vlan.ethertype == 2054:
              allow_reason = "ARP packet (in 802.1Q)... "
              allow_traffic = 1
           if eth_vlan.ethertype == 35020:
              self.logger.info("Received LLDP frame (in 802.1Q). Exiting... ")
              return
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
           self.logger.info("Received LLDP frame! Exiting... ")
           return
        #if eth.dst == '01:80:c2:00:00:0e':
           #self.logger.info("LLDP Multicast Destination found... ")
           #return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        tr = src + " -> " + dst + ", " + str(eth.ethertype)
        self.traffic.append(tr)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        action_normal = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]

        # install a flow to avoid packet_in next time
        #if out_port != ofproto.OFPP_FLOOD:
            #match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            #if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                #self.add_flow(datapath, 1, match, action_normal, msg.buffer_id)
                #return
            #else:
                #self.add_flow(datapath, 1, match, action_normal)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        if allow_traffic == 1:
           self.logger.info("Traffic allowed, reason: " + allow_reason)
           datapath.send_msg(out)
        elif out_port == ofproto.OFPP_FLOOD:
           self.logger.info("Flooding not allowed anymore... ")
           self.logger.info("Deny rule inserted to block this traffic... ")
           #self.add_flow(datapath,2, 120, 100, parser.OFPMatch
            #  (eth_dst = dst, eth_src = src, eth_type = eth_vlan.ethertype), [])

           #datapath.send_msg(out)
        else:
           self.logger.info("Traffic blocked by Controller... ")
           match = parser.OFPMatch(eth_dst = dst, eth_src = src,
               eth_type = eth_vlan.ethertype)
           #self.add_flow(datapath, 2, 120, 100, match, [])
        self.getFlows(datapath.id)


    def getFlows(self, dpid):
       datapath = 0
       self.logger.info("Datapath_ids length: %s", len(self.datapath_ids))

       for d in self.datapath_ids:
          self.logger.info("Comparing dpid %s with id %s", dpid, d.id)
          if long(d.id) == long(dpid):
             datapath = d
             self.logger.info("DPID found")
             break

       if datapath == 0:
          return "Error 404, datapath not found"

       self.flow_reply_received = 0
       self.requestFlows(datapath)
       max_timeout = 2
       while self.flow_reply_received == 0:
          max_timeout -= 0.2
          if max_timeout <= 0:
             return "Switch is not responding... "
          time.sleep(0.2)
       return self.flow_rules


    def requestFlows(self, datapath):
       ofp = datapath.ofproto
       ofp_parser = datapath.ofproto_parser
       cookie = cookie_mask = 0
       match = ofp_parser.OFPMatch()
       req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                         ofp.OFPTT_ALL,
                                         ofp.OFPP_ANY, ofp.OFPG_ANY,
                                         cookie, cookie_mask,
                                         match)
       datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
       flows = []
       for stat in ev.msg.body:
          flows.append('table_id=%s'
                     'duration_sec=%d duration_nsec=%d '
                     'priority=%d '
                     'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                     'cookie=%d packet_count=%d byte_count=%d '
                     'match=%s instructions=%s' %
                     (stat.table_id,
                      stat.duration_sec, stat.duration_nsec,
                      stat.priority,
                      stat.idle_timeout, stat.hard_timeout, stat.flags,
                      stat.cookie, stat.packet_count, stat.byte_count,
                      stat.match, stat.instructions))
       #self.logger.debug('FlowStats: %s', flows)
       self.flow_rules = flows
       self.flow_reply_received = 1



#---------------- Class for HTTP REST API -----------------------------
class SGController(ControllerBase):

   def __init__(self, req, link, data, **config):
      super(SGController, self).__init__(req, link, data, **config)
      self.sg_app = data[sg_controller_instance_name]

   @route('fw', url, methods = ['GET'], requirements = {'dpid': dpid_lib.DPID_PATTERN})
   def list_fw_rules(self, req, **kwargs):
      sg_switch = self.sg_app
      dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

      rules_table = sg_switch.getFlows(kwargs['dpid'])

      if rules_table == 0:
         return Response(status = 404)

      body = json.dumps(rules_table)
      return Response(content_type ='application/json', body = body )

   @route('fw', url2, methods = ['GET'], requirements = {'dpid': dpid_lib.DPID_PATTERN})
   def list_fw_traffic(self, req, **kwargs):
      sg_switch = self.sg_app
      body = json.dumps(sg_switch.traffic)
      return Response(content_type='application/json', body = body)