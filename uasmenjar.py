from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types, icmpv6, ipv6


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_ip = {}

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
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=20, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=20, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

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

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info("Received ARP Packet %s %s %s ", dpid, src, dst)
            arps = pkt.get_protocol(arp.arp)
            ip_src = arps.src_ip
            self.mac_to_ip[ip_src] = src
            ip_dst = arps.dst_ip
            if arps.opcode==arp.ARP_REQUEST and ip_dst in self.mac_to_ip:
            	self.logger.info("Matched MAC %s ", ip_dst)
            	arp_resp = packet.Packet()
            	arp_resp.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=self.mac_to_ip[ip_dst]))
            	arp_resp.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=self.mac_to_ip[ip_dst], src_ip=ip_dst, dst_mac=arps.src_mac, dst_ip=arps.src_ip))
            	arp_resp.serialize()
            	actions = []
            	actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))
            	out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            		in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_resp)
            	datapath.send_msg(out)
            	self.logger.info("Proxied ARP Response packet")

        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # This is an IPv6 packet, check if it's an NDP packet
            ipv6_header = pkt.get_protocol(ipv6.ipv6)
            if ipv6_header.nxt == 58:  # next_header value of 58 indicates an ICMPv6 packet
                icmpv6_header = pkt.get_protocol(icmpv6.icmpv6)
                if icmpv6_header.type_ == 135:  # type_ value of 135 indicates an NDP Neighbor Solicitation message
                    # This is an NDP Neighbor Solicitation message
                    self.logger.info("Received NDP Neighbor Solicitation %s %s %s ", dpid, src, dst)
                    ip_src = ipv6_header.src
                    self.mac_to_ip[ip_src] = src
                    ip_dst = ipv6_header.dst
                    if ip_dst in self.mac_to_ip:
                        self.logger.info("Matched MAC %s ", ip_dst)
                        ndp_resp = packet.Packet()
                        ndp_resp.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=self.mac_to_ip[ip_dst]))
                        ndp_resp.add_protocol(ipv6.ipv6(src=ip_dst, dst=ip_src))
                        ndp_resp.add_protocol(icmpv6.icmpv6(type_=136, code=0))  # type_ value of 136 indicates an NDP Neighbor Advertisement message
                        ndp_resp.serialize()
                        actions = []
                        actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                            in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ndp_resp)
                        datapath.send_msg(out)
                        self.logger.info("Proxied NDP Response packet")

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
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
