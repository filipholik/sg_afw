from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

import cProfile, pstats, StringIO
import re

import signal
import sys

# File modified to support profiling in order to verify the most
#  demanding functions
prof = cProfile.Profile() #profiling variable
PROFILING_FILENAME = 'profstats.pstats' #name of the file for storing profile info

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    #Function will be called at the end of the program
    def signal_handler(signal, frame):
        print('You pressed Ctrl+C, exiting profiling!')
        #End of profiling
        prof.disable()
        s = StringIO.StringIO()
        sortby = 'cumulative'
        ps = pstats.Stats(prof, stream=s).sort_stats(sortby)
        ps.dump_stats(PROFILING_FILENAME)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler) #register signal for prof.

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs['stplib']

        prof.enable() #start profiling

        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        # 2960111173765568, 2991443865190400
        '''
        config = {dpid_lib.str_to_dpid('000aa0b3ccf34000'):
                     {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('000a8434970209c0'):
                     {'bridge': {'priority': 0x1000}}
                  }
        '''
        config = {dpid_lib.str_to_dpid('000a8434970209c0'):
                     {'bridge': {'priority': 0x9000},
                      'ports': {48: {'priority': 1, 'path_cost': 1},
                                2: {'enable': 'False'},
                                3: {'enable': 'False'},
                                10: {'enable': 'False'},
                                47: {'priority': 127, 'path_cost': 48}}},
                  dpid_lib.str_to_dpid('000aa0b3ccf34000'):
                     {'bridge': {'priority': 0x1000},
                    'ports': {48: {'priority': 1, 'path_cost': 1},
                              2: {'enable': 'False'},
                              3: {'enable': 'False'},
                              10: {'enable': 'False'},
                              47: {'priority': 127, 'path_cost': 48}}}
                  }

        #cProfile.run('re.stp_set_config(config)', 'profile_stats')
        self.stp.set_config(config)
        '''
        pr.disable()
        s = StringIO.StringIO()
        sortby = 'cumulative'
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.dump_stats('stats.txt')
        print s.getvalue()
        '''

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
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions)

    def add_flow(self, datapath, priority, idle_timeout, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, table_id = 100, idle_timeout = idle_timeout,
                                instructions=inst)
        datapath.send_msg(mod)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE, table_id = 100,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # Patch for our specific topology (two switches connected via duplicated cables),
        # prevents learning from specific devices (VM1 - VM6) on wrong links
        if str(dpid) == "2991443865190400":
            if src == "fa:16:3e:57:f6:e8" and in_port != 10:
                self.logger.info("Inconsistent MAC to Port mapping for VM6! ")
                self.mac_to_port[dpid][src] = 10
        if str(dpid) == "2960111173765568":
            if src == "fa:16:3e:30:cc:04" and in_port != 2:
                self.logger.info("Inconsistent MAC to Port mapping for VM1! ")
                self.mac_to_port[dpid][src] = 2

        self.logger.info("MAC_to_PORT: %s", self.mac_to_port)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst) #eth_src=src , eth_type=0x0800
            self.add_flow(datapath, 1, 30, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])

