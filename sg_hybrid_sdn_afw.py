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

# Adaptive Firewall for Smart Grid Security, 3.3.1

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from file_loader import FileLoader
from ryu.ofproto import inet
from ryu.lib.packet import ipv4
from ryu.lib.packet import vlan

from ryu.ofproto.ofproto_v1_3 import OFPG_ANY

import time
import json
import logging
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib

from switchpoll import *
from threading import *


sg_controller_instance_name = 'sg_controller_api_app'
url = '/fw/rules/{dpid}'
url2 = '/fw/traffic/{dpid}'

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = { 'wsgi' : WSGIApplication }

    flowtablesdict = {} #Flow Tables of all switches
    trafficdict = {} #DPIDS, Array of captured traffic - dicts
    #fileloader
    #datapathdict

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapathdict = {} #for storing datapaths
        wsgi = kwargs['wsgi']
        wsgi.register(SGController, {sg_controller_instance_name : self})

        #Thread for periodic polling of information from switches
        switchPoll = SwitchPoll()
        pollThread = Thread(target=switchPoll.run, args=(5,self.datapathdict))
        pollThread.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        self.datapathdict[datapath.id] = datapath

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
        self.add_flow(datapath, 10, 180, 100, parser.OFPMatch(eth_type=0x88cc), actions)

        #Hybrid SDN Config -----------------------------------------
        #BDDP frames
        self.add_flow(datapath, 10, 180, 100, parser.OFPMatch(eth_type=0x8999), actions)

        #ARP frames
        #self.add_flow(datapath, 1, 180, 100, parser.OFPMatch(eth_type=2054), action_normal)
        # first instruction to table 200 must be set
        instruction_200 = [parser.OFPInstructionGotoTable(200)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath, table_id=100, command=ofproto.OFPFC_ADD, idle_timeout = 180,
                                priority = 2, match=parser.OFPMatch(eth_type=2054), instructions=instruction_200)
        datapath.send_msg(mod)
        # rule itself must be inserted in table 200 (supports copying of packets)
        self.add_flow(datapath, 2, 180, 200, parser.OFPMatch(eth_type=2054), action_copy)

        #Deny everything else - send it to the controller
        self.add_flow(datapath, 1, 180, 100, match, actions)

        self.fw_init(datapath)


    def fw_init(self, datapath):
      parser = datapath.ofproto_parser
      ofproto = datapath.ofproto
      self.logger.info("FW Initialization started (dpid: %d)...", datapath.id)
      self.fileLoader = FileLoader()
      topology = self.fileLoader.getTopology()

      listofmatches = self.fileLoader.getFWRulesMatches(parser, datapath.id)
      self.logger.info("Topology loaded... \nFile with rules loaded... \nApplying %s rules...",
                       len(listofmatches))

      for match in listofmatches:
        self.add_flow(datapath, 5, 120, 100, match,
             [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])

    def add_flow(self, datapath, priority, idle_timeout, table_id, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout, instructions=inst,
                                    table_id=table_id, flags=ofproto.OFPFF_SEND_FLOW_REM)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=idle_timeout, instructions=inst,
                                    table_id=table_id, flags=ofproto.OFPFF_SEND_FLOW_REM)
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
        #self.logger.info("F: protocol: %s, %s", eth, eth_vlan)
        #test = packet.Packet(array.array('B', ev.msg.data))
        #for p in test.protocols:
        #   self.logger.info("Protocols: %s", p)

        allow_traffic = 0
        allow_reason = ""
        if eth.ethertype == ether_types.ETH_TYPE_8021Q:
           #self.logger.info("F: Received 802.1Q frame!")
           if eth_vlan.ethertype == 2054:
              allow_reason = "ARP packet (in 802.1Q)... "
              #allow_traffic = 1
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

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        self.captureTraffic(ev)

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
           self.add_flow(datapath,3, 10, 100, parser.OFPMatch
             (eth_dst = dst, eth_src = src, eth_type = eth_vlan.ethertype), [])

           #datapath.send_msg(out)
        else:
           self.logger.info("Traffic blocked by Controller... ")
           match = parser.OFPMatch(eth_dst = dst, eth_src = src,
               eth_type = eth_vlan.ethertype)
           self.add_flow(datapath, 3, 10, 100, match, [])


    def captureTraffic(self, ev):
      msg = ev.msg
      datapath = msg.datapath
      pkt = packet.Packet(msg.data)
      eth = pkt.get_protocols(ethernet.ethernet)[0]
      eth_type = eth.ethertype
      #if encapsulated in VLAN - 802.1Q
      if eth.ethertype == ether_types.ETH_TYPE_8021Q:
        eth_vlan = pkt.get_protocols(vlan.vlan)[0]
        eth_type = eth_vlan.ethertype

      capturedTraffic = {}
      #message = eth.src + " -> " + eth.dst + ", proto: " + str(eth.ethertype)
      '''message = []
      message.append('eth_src = %s'%(eth.src))
      message.append('eth_dst = %s'%(eth.dst))
      message.append('l2_proto = %d'%(eth_type))'''

      capturedTraffic['eth_src'] = eth.src
      capturedTraffic['eth_dst'] = eth.dst
      capturedTraffic['eth_type'] = eth_type

      allTraffic = []
      if datapath.id in self.trafficdict:
        allTraffic = self.trafficdict[datapath.id]
        if capturedTraffic in allTraffic:
          self.logger.info('Traffic already captured... ')
          return

      allTraffic.append(capturedTraffic)
      self.trafficdict[datapath.id] = allTraffic

      self.logger.info('New traffic captured... ')

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
      self.logger.info('Flow_removed notification received... ')
      msg = ev.msg
      dp = msg.datapath
      ofp = dp.ofproto

      matchfields = msg.match
      #OFPMatch(oxm_fields={'eth_src': 'fa:16:3e:30:cc:04', 'eth_dst': 'fa:16:3e:57:f6:e8', 'eth_type': 2054})
      eth_src = 0
      eth_dst = 0
      eth_type = 0
      for the_key, value in matchfields.iteritems():
        if the_key == "eth_src":
          eth_src = value
        if the_key == "eth_dst":
          eth_dst = value
        if the_key == "eth_type":
          eth_type = value

      allTraffic = self.trafficdict[dp.id]
      for tr in allTraffic:
        self.logger.info('SRC: ' + tr['eth_src'] + " DST: " +tr['eth_dst'])

      if matchfields in allTraffic:
        self.logger.info('Deleting existing traffic' )
      else:
        self.logger.info('Traffic not found')


      #self.logger.info('Field: ' + the_key + ' value: ' + value)




      if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
        reason = 'IDLE TIMEOUT'
      elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
        reason = 'HARD TIMEOUT'
      elif msg.reason == ofp.OFPRR_DELETE:
        reason = 'DELETE'
      elif msg.reason == ofp.OFPRR_GROUP_DELETE:
        reason = 'GROUP DELETE'
      else:
        reason = 'unknown'

      '''self.logger.info('OFPFlowRemoved received: '
                            'cookie=%d priority=%d reason=%s table_id=%d '
                            'duration_sec=%d duration_nsec=%d '
                            'idle_timeout=%d hard_timeout=%d '
                            'packet_count=%d byte_count=%d match.fields=%s',
                            msg.cookie, msg.priority, reason, msg.table_id,
                            msg.duration_sec, msg.duration_nsec,
                            msg.idle_timeout, msg.hard_timeout,
                            msg.packet_count, msg.byte_count, msg.match)
      '''


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
      self.logger.info('Flow_stats_reply received... ')
      flows = []
      for stat in ev.msg.body:
        '''flows.append('table_id=%s '
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
                      stat.match, stat.instructions))'''
        flows.append('table_id = %s'%(stat.table_id))
        flows.append('priority = %d'%(stat.priority))
        flows.append('duration_sec = %d'%(stat.duration_sec))
        flows.append('idle_timeout = %d'%(stat.idle_timeout))
        flows.append('packet_count = %d'%(stat.packet_count))
        flows.append('match = %s'%(stat.match))
        flows.append('instructions = %s'%(stat.instructions))

      #self.logger.info('FlowStats: %s', flows)
      datapath = ev.msg.datapath
      self.flowtablesdict[datapath.id] = flows


    def getFlows(self, dpid):
      if int(dpid) not in self.flowtablesdict:
        return "Datapath ID entry not found... "
      else:
        return self.flowtablesdict[int(dpid)]

    def getTraffic(self, dpid):
      if int(dpid) not in self.trafficdict:
        return "Datapath ID entry not found... "
      else:
        allTraffic = self.trafficdict[int(dpid)]
        trlist = []
        for tr in allTraffic:
          trlist.append(tr['eth_src'])
          trlist.append(tr['eth_dst'])
          trlist.append(tr['eth_type'])

        #self.logger.info('SRC: ' + tr['eth_src'] + " DST: " +tr['eth_dst'])
        return trlist

    def setNewFWRule(self, data):
      self.logger.info('New FW rule received... ' )
      rule = self.fileLoader.createANewRule(data)
      #self.logger.info('Rule-type: ' + str(rule.twoway) )

      for dpid in self.datapathdict:
        datapath = self.datapathdict[dpid]
        match = self.fileLoader.createMatch(rule, datapath.ofproto_parser, dpid)
        if match == 0:
          continue
        else:
          self.applyNewFWRule(datapath, match)
          if rule.ruletype == 2:
            rule = self.fileLoader.swapRuleSrcDst(rule)
            match = self.fileLoader.createMatch(rule, datapath.ofproto_parser, dpid)
            if match == 0:
              continue
            self.applyNewFWRule(datapath, match)

      #self.logger.info('Data2: ' +str(data['data']) )
      return 200

    def applyNewFWRule(self, datapath, match):
      parser = datapath.ofproto_parser
      ofproto = datapath.ofproto
      self.add_flow(datapath, 5, 120, 100, match,
                    [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])
      self.logger.info('New FW rule applied... ' )

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
            [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
      msg = ev.msg
      self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
                      'message=%s',
                      msg.type, msg.code, utils.hex_array(msg.data))


#---------------- Class for HTTP REST API -----------------------------
class SGController(ControllerBase):
  def __init__(self, req, link, data, **config):
    super(SGController, self).__init__(req, link, data, **config)
    self.sg_app = data[sg_controller_instance_name]
    self.sg_switch = self.sg_app

  @route('fw', url, methods = ['GET'], requirements = {'dpid': dpid_lib.DPID_PATTERN})
  def list_fw_rules(self, req, **kwargs):
    #sg_switch = self.sg_app
    dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

    rules_table = self.sg_switch.getFlows(kwargs['dpid'])

    if rules_table == 0:
      return Response(status = 404)

    body = json.dumps(rules_table)
    return Response(content_type ='application/json', body = body )

  @route('fw', url2, methods = ['GET'], requirements = {'dpid': dpid_lib.DPID_PATTERN})
  def list_fw_traffic(self, req, **kwargs):
    #sg_switch = self.sg_app
    traffic = self.sg_switch.getTraffic(kwargs['dpid'])
    body = json.dumps(traffic)
    return Response(content_type='application/json', body = body)

  @route('fw', url, methods = ['POST'], requirements = {'dpid': dpid_lib.DPID_PATTERN})
  def insert_fw_rule(self, req, **kwargs):
    rule = json.loads(req.body)
    status = self.sg_switch.setNewFWRule(rule)
    return Response(status = status)

    return Response(content_type='application/json', body = body)




