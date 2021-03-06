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

# Adaptive Firewall for Smart Grid Security, 3.5.1

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
from ryu import utils
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib

from switchpoll import *
from threading import *

import re
import copy


sg_controller_instance_name = 'sg_controller_api_app'
url_rules = '/fw/rules/{dpid}'
url_delrule = '/fw/delrule/{dpid}'
url_traffic_denied = '/fw/traffic_denied/{dpid}'
url_traffic_allowed = '/fw/traffic_allowed/{dpid}'
url_topology = '/fw/topology'
url_traffic = '/fw/traffic'

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = { 'wsgi' : WSGIApplication }

    #VARIABLES to set
    IDLE_TIMEOUTS = 180 #TODO Set idle_timeouts to 0 = infinity (180 only for testing purposes)
    DENY_RULES_IDLE_TIMEOUT = 30 #How long unallowed traffic will be blocked
    HW_TABLE_ID = 100 #Set id of the flow table (100 = HP switches)
    SWITCH_POLL_TIMER = 1 #How often are switches queried (in seconds)
    PACKET_HISTORY_BUFFER_SIZE = 10 #In seconds
    MAC_SPOOFPROT_MAX_PPS = 100 #Maximum number of packets, which can be sent per second

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
        pollThread = Thread(target=switchPoll.run, args=(self.SWITCH_POLL_TIMER,self.datapathdict))
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

        #LLDP frames
        self.add_flow(datapath, 10, self.IDLE_TIMEOUTS, self.HW_TABLE_ID, parser.OFPMatch(eth_type=0x88cc), actions)

        #Hybrid SDN Config -----------------------------------------
        #BDDP frames
        self.add_flow(datapath, 10, self.IDLE_TIMEOUTS, self.HW_TABLE_ID, parser.OFPMatch(eth_type=0x8999), actions)

        #ARP frames - send in normal
        self.add_flow(datapath, 10, self.IDLE_TIMEOUTS, self.HW_TABLE_ID, parser.OFPMatch(eth_type=2054), action_normal)

        #Deny everything else - send it to the controller
        self.add_flow(datapath, 1, self.IDLE_TIMEOUTS, self.HW_TABLE_ID, match, actions)

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
        self.add_flow(datapath, 5, self.IDLE_TIMEOUTS, self.HW_TABLE_ID, match,
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
        self.logger.info("Added flow: %s, %s", datapath, match)

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
           self.add_flow(datapath, 3, self.DENY_RULES_IDLE_TIMEOUT, self.HW_TABLE_ID, parser.OFPMatch
             (eth_dst = dst, eth_src = src, eth_type = eth_vlan.ethertype), [])

           #datapath.send_msg(out)
        else:
           self.logger.info("Traffic blocked by Controller... ")
           match = parser.OFPMatch(eth_dst = dst, eth_src = src,
               eth_type = eth_vlan.ethertype)
           self.add_flow(datapath, 3, self.DENY_RULES_IDLE_TIMEOUT, self.HW_TABLE_ID, match, [])


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
      capturedTraffic['eth_src'] = eth.src
      capturedTraffic['eth_dst'] = eth.dst
      capturedTraffic['eth_type'] = eth_type
      capturedTraffic['priority'] = 3

      allTraffic = []
      if datapath.id in self.trafficdict:
        allTraffic = self.trafficdict[datapath.id]
        if capturedTraffic in allTraffic:
          self.logger.info('Traffic already captured... ')
          return

      allTraffic.append(capturedTraffic)
      self.trafficdict[datapath.id] = allTraffic

      self.logger.info('New traffic captured... ')

    def deleteTraffic(self, dpid, matchString):
      if dpid in self.trafficdict:
        allTraffic = self.trafficdict[dpid]
        if matchString in allTraffic:
          self.logger.info('Deleting existing traffic' )
          allTraffic.remove(deleted)
          self.trafficdict[dpid] = allTraffic
          return 1
      return 0

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
      deleted = {}
      deleted['eth_src'] = eth_src
      deleted['eth_dst'] = eth_dst
      deleted['eth_type'] = eth_type

      self.deleteTraffic(dp.id, deleted)


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        self.logger.info('Flow_stats_reply received... ')
        datapath = ev.msg.datapath
        flows = []
        flowdict = {}

        for stat in ev.msg.body:
            flowdict = {}
            flowdict['table_id'] = stat.table_id
            flowdict['priority'] = stat.priority
            flowdict['duration_sec'] = stat.duration_sec
            flowdict['idle_timeout'] = stat.idle_timeout
            flowdict['packet_count'] = stat.packet_count
            flowdict['match'] = str(stat.match)
            flowdict['instructions'] = str(stat.instructions)
            matchdict = self.createMatchDict(str(stat.match))
            flowdict['matchdict'] = matchdict

            match = stat.match
            #self.logger.info(match.OFPMatch)

            previous_flowdict = self.flow_exists(datapath.id, flowdict)
            if previous_flowdict != 0:
                flowdict = self.add_packet_count_history(previous_flowdict, flowdict)
                #self.logger.info('FlowHistory: %s', flowdict['packet_count_history'])
            flows.append(flowdict)

        #self.logger.info('FlowStats: %s', flows)
        self.flowtablesdict[datapath.id] = flows
        self.check_mac_spoofing(ev.msg)

    def flow_exists(self, dpid, newflowdict):
        if dpid in self.flowtablesdict:
            for flowdict in self.flowtablesdict[dpid]:
                if newflowdict['table_id'] == flowdict['table_id'] and newflowdict['priority'] == flowdict['priority'] and newflowdict['idle_timeout'] == flowdict['idle_timeout'] and newflowdict['match'] == flowdict['match'] and newflowdict['instructions'] == flowdict['instructions']:
                    return flowdict
        #self.logger.info('No match found...')
        return 0

    def add_packet_count_history(self, old_flow, new_flow):
        history = []
        if 'packet_count_history' not in old_flow:
            history.append(new_flow['packet_count'])
            new_flow['packet_count_history'] = history
            return new_flow

        #Already exists
        packet_count_history = old_flow['packet_count_history']
        if len(packet_count_history) >= self.PACKET_HISTORY_BUFFER_SIZE:
            packet_count_history.pop(0)
        packet_count_history.append(new_flow['packet_count'])
        new_flow['packet_count_history'] = packet_count_history
        return new_flow

    def check_mac_spoofing(self, msg):
        #TODO
        self.logger.info("Checking MAC address spoofing... ")
        for dpid in self.flowtablesdict:
            flows = self.flowtablesdict[dpid]
            for flow in flows:
                if 'match' in flow:
                    match = flow['matchdict']
                    if 'packet_count_history' in flow:
                        history = copy.deepcopy(flow['packet_count_history'])
                        if len(history) >= 2:
                            if history.pop() - history.pop() >= self.MAC_SPOOFPROT_MAX_PPS:
                                self.logger.info("Number of PPS exceeded. Enabling MAC spoofing protection!")
                                self.disable_flow(msg, match)
                    #self.logger.info("Count: %s, match: %s ", count, match)

    def disable_flow(self, msg, match):
        match = copy.deepcopy(match)
        typehex = int(match['eth_type'])
        #typehex = '{0:x}'.format(int(typehex))
        typehex = hex(typehex)
        self.logger.info("Match proto: %s", str(typehex))
        match['eth_type'] = typehex
        self.deleteExistingRule(match)
        self.logger.info("Flow deleted")
        return 1

    @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
    def aggregate_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('AggregateStats: packet_count=%d byte_count=%d '
                      'flow_count=%d',
                      body.packet_count, body.byte_count,
                      body.flow_count)


    def createMatchDict(self, matchstring):
      #sepparated = matchstring.split(" ")
      single = matchstring.replace("'","")
      #single = single.replace("'","")
      single = re.split('{|, | ',matchstring)
      #self.logger.info('---')
      matchdict = {}
      previous = ""
      for w in single:
        w = w.replace("'","")
        w = w.replace("}","")
        w = w.replace(")","")
        #self.logger.info('match: %s', w)
        if previous == "eth_dst:":
          matchdict['eth_dst'] = w
        if previous == "eth_src:":
          matchdict['eth_src'] = w
        if previous == "eth_type:":
          matchdict['eth_type'] = w

        previous = w

      #self.logger.info('---')
      return matchdict

    def getFlows(self, dpid):
      if int(dpid) not in self.flowtablesdict:
        self.logger.info('DPID not found... ' )
        return 0
      else:
        return self.flowtablesdict[int(dpid)]

    def getTraffic(self, dpid, allowed):
        traffic = []
        flows = self.getFlows(dpid)
        if flows == 0:
            return 0
        for flow in flows:
          if 'match' in flow:
            newMatchDict = flow['matchdict']
            if 'packet_count_history' in flow:
                newMatchDict['packet_count_history'] = flow['packet_count_history']
            else:
                newMatchDict['packet_count_history'] = 0
            if allowed == 1 and flow['priority'] == 3:
              continue
            if allowed == 0 and flow['priority'] != 3:
              continue
            newMatchDict['priority'] = flow['priority']
            traffic.append(newMatchDict)
        return traffic

    #For traffic visualization
    def getTrafficVis(self):
        traffic = []
        for dpid in self.flowtablesdict:
            flows = self.flowtablesdict[dpid]
            for flow in flows:
                if 'match' in flow:
                    newMatchDict = flow['matchdict']
                    if flow['priority'] == 3:
                        continue
                    newMatchDict['priority'] = flow['priority']
                    traffic.append(newMatchDict)

        return self.fileLoader.createVisualizationData(traffic)

    def deleteExistingRule(self, data):
        self.logger.info('New request for deleting FW rule received... %s', data['eth_type'] )
        rule = self.fileLoader.createANewRule(data)

        for dpid in self.datapathdict:
            datapath = self.datapathdict[dpid]
            match = self.fileLoader.createMatch(rule, datapath.ofproto_parser, dpid)
            self.logger.info('Match: %s ', match )
            if match == 0:
                continue
            else:
                self.deleteRule(datapath, match, int(rule.rulepriority))
                if rule.ruletype == 2 and rule.dst != str('ff:ff:ff:ff:ff:ff'):
                    rule = self.fileLoader.swapRuleSrcDst(rule)
                    match = self.fileLoader.createMatch(rule, datapath.ofproto_parser, dpid)
                    self.deleteRule(datapath, match, int(rule.rulepriority))
        return 200

    def setNewFWRule(self, data):
      self.logger.info('New FW rule received... ' )
      rule = self.fileLoader.createANewRule(data)

      for dpid in self.datapathdict:
        datapath = self.datapathdict[dpid]
        match = self.fileLoader.createMatch(rule, datapath.ofproto_parser, dpid)
        self.logger.info('Destination MAC: %s', rule.dst)
        if match == 0:
            self.logger.info('Match couldnt be created! DPID: %s', dpid)
            continue
        else:
          self.deleteRule(datapath, match, 3)
          self.applyNewFWRule(datapath, match, int(rule.rulepriority))
          if rule.ruletype == 2 and rule.dst != str('ff:ff:ff:ff:ff:ff'):
            rule2 = self.fileLoader.swapRuleSrcDst(rule)
            match2 = self.fileLoader.createMatch(rule2, datapath.ofproto_parser, dpid)
            self.deleteRule(datapath, match2, 3)
            self.applyNewFWRule(datapath, match2, int(rule.rulepriority))
          else:
            self.logger.info('One way rule only or destination broadcast! ')
      return 200

    def applyNewFWRule(self, datapath, match, priority):
      parser = datapath.ofproto_parser
      ofproto = datapath.ofproto
      self.add_flow(datapath, priority, self.IDLE_TIMEOUTS, self.HW_TABLE_ID, match,
                    [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])
      self.logger.info('New FW rule applied... ' )

    def deleteRule(self, datapath, match, priority):
      ofproto = datapath.ofproto
      parser = datapath.ofproto_parser
      #inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

      mod = parser.OFPFlowMod(datapath=datapath, match=match, priority = priority, table_id = self.HW_TABLE_ID,
                              out_port = ofproto.OFPP_ANY, out_group = ofproto.OFPG_ANY,
                              command = ofproto.OFPFC_DELETE)
      datapath.send_msg(mod)
      self.logger.info('Duplicated deny rule deleted... ' )


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

  @route('fw', url_rules, methods = ['GET'], requirements = {'dpid': dpid_lib.DPID_PATTERN})
  def list_fw_rules(self, req, **kwargs):
    #sg_switch = self.sg_app
    dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
    flows = self.sg_switch.getFlows(kwargs['dpid'])

    if flows == 0:
      return Response(status = 404)
    body = json.dumps(flows)
    return Response(content_type ='application/json', body = body )

  @route('fw', url_traffic_denied, methods = ['GET'], requirements = {'dpid': dpid_lib.DPID_PATTERN})
  def list_fw_traffic_denied(self, req, **kwargs):
    traffic = self.sg_switch.getTraffic(kwargs['dpid'], 0)
    body = json.dumps(traffic)
    return Response(content_type='application/json', body = body)

  @route('fw', url_traffic_allowed, methods = ['GET'], requirements = {'dpid': dpid_lib.DPID_PATTERN})
  def list_fw_traffic_allowed(self, req, **kwargs):
    traffic = self.sg_switch.getTraffic(kwargs['dpid'], 1)
    body = json.dumps(traffic)
    return Response(content_type='application/json', body = body)

  @route('fw', url_rules, methods = ['POST'], requirements = {'dpid': dpid_lib.DPID_PATTERN})
  def insert_fw_rule(self, req, **kwargs):
    rule = json.loads(req.body)
    status = self.sg_switch.setNewFWRule(rule)
    return Response(status = status)

  @route('fw', url_delrule, methods = ['POST'], requirements = {'dpid': dpid_lib.DPID_PATTERN})
  def delete_fw_rule(self, req, **kwargs):
    rule = json.loads(req.body)
    status = self.sg_switch.deleteExistingRule(rule)
    return Response(status = status)

  @route('fw', url_topology, methods = ['GET'], requirements = {})
  def list_fw_topology(self, req, **kwargs):
    topologydict = {
    "nodes":[
    {"name":"Switch 1","group":1},
    {"name":"Switch 2","group":2},
		{"name":"IED1","group":1},
		{"name":"IED2","group":1},
		{"name":"Coll1","group":1},
		{"name":"IED3","group":2},
    {"name":"IED4","group":2},
    {"name":"Coll2","group":2},
	  ],
	  "links":[
		{"source":0,"target":1,"weight":10},
		{"source":0,"target":1,"weight":10},
    {"source":0,"target":2,"weight":3},
    {"source":0,"target":3,"weight":3},
    {"source":0,"target":4,"weight":3},
    {"source":1,"target":5,"weight":3},
    {"source":1,"target":6,"weight":3},
    {"source":1,"target":7,"weight":3}
	  ]
    }
    body = json.dumps(topologydict)
    return Response(content_type='application/json', body = body)

  @route('fw', url_traffic, methods = ['GET'], requirements = {})
  def list_fw_traffic(self, req, **kwargs):
    traffic = self.sg_switch.getTrafficVis()

    trafficdict = {
     "name": "traffic",
     "children": [
      {
       "name": "L2",
       "children": [
        {
         "name": "0x0800",
         "children": [
          {"name": "IED1 <-> IED3", "size": 3938},
          {"name": "IED2 <-> IED4", "size": 3812}
         ]
        },
        {
         "name": "GOOSE",
         "children": [
          {"name": "IED1 -> Coll1", "size": 3534}
         ]
        },
        {
         "name": "ARP",
         "children": [
          {"name": "IED4", "size": 7074}
         ]
        }
       ]
      }
      ]}
    body = json.dumps(traffic)
    return Response(content_type='application/json', body = body)





