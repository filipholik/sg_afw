#For versions  3.2.1+
import os
from ryu.ofproto import ofproto_v1_3

class FileLoader():
  mac_addresses = {'0':'00:00:00:00:00:00'}
  rules = []
  topology = 0
  path = 'ryu/ryu/app/sg'

  def loadRulesFile(self):
      del self.rules[:] #Otherwise rules on second switch loaded twice
      with open(os.path.join(self.path, 'rules.txt'), 'r') as f:
          for line in f:
             if "//" in line:
                continue
             if "allow" in line:
                self.rules.append(line)
             else:
                sepparated = line.split()
                position = 0
                for w in sepparated:
                   if position == 0:
                      position = w
                   else:
                      #self.device_mac[position] = w
                      self.mac_addresses[position] = w
                      position = 0

  def loadTopologyFile(self):
    self.topology = Topology()
    with open(os.path.join(self.path, 'topology.txt'), 'r') as f:
      for line in f:
        if "//" in line:
          continue
        sepparated = line.split()
        if len(sepparated) == 3:
          #Loading networking devices
          transit = 0
          position = 0
          switch_name = ""
          for w in sepparated:
            if position == 0:
              switch_name = w
            if position == 1:
              transit = int(w)
            if position == 2:
              self.topology.addSwitchNames(switch_name, w)
              if transit == 1:
                self.topology.addTransitDevice(w)
            position += 1

        if len(sepparated) == 2:
          #Loading mapping of devices to switches
          position = 0
          switch_name = ""
          for w in sepparated:
            if position == 0:
              switch_name = w
            if position == 1:
              switch_dpid = self.topology.getSwitchDPID(switch_name)
              if switch_dpid == 0:
                break
              else:
                self.topology.addAccessDevice(switch_dpid, w)
            position += 1
    return 1

  def get_rules_mac(self):
      self.loadRulesFile()
      allowed_rules = []
      for rule in self.rules:
         sepparated = rule.split()
         reading = 0
         new_rule = Rule()

         for w in sepparated:
            if w == 'deny':
               break

            if reading == 1:
               new_rule.src = (self.mac_addresses[w])
            if reading == 2:
               new_rule.dst = (self.mac_addresses[w])
            if reading == 3:
               new_rule.l2_proto = w
            if reading == 4:
               new_rule.l3_proto = int(w)
            if reading == 5:
               new_rule.ipv4_src = w
            if reading == 6:
               new_rule.ipv4_dst = w
            if reading == 7:
              if new_rule.l3_proto == 6:
                new_rule.tcp_source = w
              else:
                new_rule.udp_source = w
            if reading == 8:
              if new_rule.l3_proto == 6:
                new_rule.tcp_destination = w
              else:
                new_rule.udp_destination = w
              allowed_rules.append(new_rule)
            reading = reading + 1
      return allowed_rules

  def getTopology(self):
    self.loadTopologyFile()
    return self.topology

  def getFWRulesMatches(self, parser, dpid):
    listofrules = self.get_rules_mac()
    listofmatches = []
    for rule in listofrules:
      match = self.createMatch(rule, parser, dpid)
      if match != 0:
        listofmatches.append(match)
    return listofmatches

  def createMatch(self, rule, parser, dpid):
    if self.isRuleNeeded(rule, dpid) != 1:
      return 0

    if rule.src == 0 or rule.dst == 0 or rule.l2_proto == 0:
      return parser.OFPMatch()
    #L2 rule
    if rule.l3_proto == 0:
      return parser.OFPMatch(eth_dst = rule.dst, eth_src = rule.src,
                eth_type = int(rule.l2_proto, 16))
    #L3 proto only
    if rule.ipv4_src == 0 or rule.ipv4_dst == 0:
      return parser.OFPMatch(eth_dst = rule.dst, eth_src = rule.src,
                eth_type = int(rule.l2_proto, 16), ip_proto = int(rule.l3_proto))
    #L3 rule - not UDP or TCP
    if rule.l3_proto != 6 and rule.l3_proto != 17:
      return parser.OFPMatch(eth_dst = rule.dst, eth_src = rule.src,
                eth_type = int(rule.l2_proto, 16), ip_proto = int(rule.l3_proto),
                ipv4_src = rule.ipv4_src, ipv4_dst = rule.ipv4_dst)
    #L4 rule
    if rule.tcp_source != 0 or rule.tcp_destination != 0:
      #TCP rule
      return parser.OFPMatch(eth_dst = rule.dst, eth_src = rule.src,
                eth_type = int(rule.l2_proto, 16), ip_proto = int(rule.l3_proto),
                ipv4_src = rule.ipv4_src, ipv4_dst = rule.ipv4_dst,
                tcp_src = int(rule.tcp_source), tcp_dst = int(rule.tcp_destination))
    else:
      #UDP rule
      return parser.OFPMatch(eth_dst = rule.dst, eth_src = rule.src,
                eth_type = int(rule.l2_proto, 16), ip_proto = int(rule.l3_proto),
                ipv4_src = rule.ipv4_src, ipv4_dst = rule.ipv4_dst,
                udp_src = int(rule.udp_source), udp_dst = int(rule.udp_destination))

  #Function verifies, if the rule is needed to be inserted on the particular switch
  def isRuleNeeded(self, rule, dpid):
    if str(dpid) in self.topology.transit_devices:
      return 1
    #Device is access switch
    if str(dpid) not in self.topology.access_devicesdict:
      self.topology.getErr()
      return -1
    else:
      macs = self.topology.access_devicesdict[str(dpid)]
      if rule.src in macs or rule.dst in macs:
        return 1
      else:
        return 0


class Rule():
    src = 0
    dst = 0
    l2_proto = 0
    l3_proto = 0
    ipv4_src = 0
    ipv4_dst = 0
    tcp_source = 0
    tcp_destination = 0
    udp_source = 0
    udp_destination = 0


class Topology():
    access_devicesdict = {} #dpids, end devices macs
    transit_devices = [] #dpids
    switches_namesdict = {} #names, dpid

    def addSwitchNames(self, name, dpid):
      if name not in self.switches_namesdict:
        self.switches_namesdict[name] = dpid
        return 1
      else:
        return 0

    def getSwitchDPID(self, name):
      if name in self.switches_namesdict:
        return self.switches_namesdict[name]
      else:
        return 0

    def addTransitDevice(self, dpid):
      if dpid not in self.transit_devices:
        self.transit_devices.append(dpid)
        return 1
      else:
        return 0


    def addAccessDevice(self, dpid, mac):
      if dpid in self.access_devicesdict:
        connected_devices = self.access_devicesdict[dpid]
        if mac in connected_devices:
          return 0
        else:
          connected_devices.append(mac)
          self.access_devicesdict[dpid] = connected_devices
      else:
        new_device = []
        new_device.append(mac)
        self.access_devicesdict[dpid] = new_device

      return 1



