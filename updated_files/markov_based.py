from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, icmp, in_proto, ether_types
import networkx as nx
import hashlib
from ryu.lib import hub
import time
import random


class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    BytesArray = [0, 0]
    TimeArray = [0, 0]
    index = 0
    dic = {}

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.network = nx.Graph()
        self.mac_to_port = {}
        self.mac_to_dpid = {}
        self.link_traffic = {
            ('s2', 's4'): 0,
            ('s3', 's4'): 0
        }
        self.d = {
            (1, 2): [2, 1],
            (1, 3): [3, 1],
            (2, 4): [2, 1],
            (3, 4): [2, 2],
        }
        self.check = set()
        self.SwitchMap = {}
        self.transition_probs = []
        self.alpha = 0.8
        self.paths = []
        self.logger.info("Initializing controller...")
        self.define_topology()
        hub.spawn(self.start_periodic_utilization_display)

    def define_topology(self):
        self.network.add_edges_from([
            (1, 2, {'src_port': 2, 'dst_port': 1}),
            (1, 3, {'src_port': 3, 'dst_port': 1}),
            (2, 4, {'src_port': 2, 'dst_port': 1}),
            (3, 4, {'src_port': 2, 'dst_port': 2}),
        ])
        self.paths = list(nx.all_shortest_paths(self.network, source=1, target=4))
        num_paths = len(self.paths)
        if num_paths > 0:
            self.transition_probs = [1.0 / num_paths] * num_paths

    def get_path_utilization(self, path):
        util = 0
        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            link1 = (f's{u}', f's{v}')
            link2 = (f's{v}', f's{u}')
            if link1 in self.link_traffic:
                util += self.link_traffic[link1]
            elif link2 in self.link_traffic:
                util += self.link_traffic[link2]
        return util

    def update_transition_probs(self):
        if not self.paths:
            return
        utils = [self.get_path_utilization(p) for p in self.paths]
        inv_utils = [1/u if u > 0 else 1e6 for u in utils]
        total = sum(inv_utils)
        new_probs = [w/total for w in inv_utils]
        if len(self.transition_probs) != len(new_probs):
            self.transition_probs = new_probs
        else:
            self.transition_probs = [
                self.alpha * old + (1 - self.alpha) * new
                for old, new in zip(self.transition_probs, new_probs)
            ]
        self.logger.info(f"Updated transition probabilities: {self.transition_probs}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.__add_flow(datapath, 0, match, actions)
        self.SwitchMap[datapath.id] = datapath

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)
        if not eth:
            return
        eth = eth[0]
        self.mac_to_port.setdefault(datapath.id, {})[eth.src] = in_port
        self.mac_to_dpid[eth.src] = datapath.id

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            src_ip, dst_ip = ipv4_pkt.src, ipv4_pkt.dst
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                src_port, dst_port = tcp_pkt.src_port, tcp_pkt.dst_port
                if all([src_ip, dst_ip, src_port, dst_port]):
                    if not self.paths or not self.transition_probs:
                        self.logger.warning("No available paths or transition probabilities.")
                        return
                    selected_path = random.choices(self.paths, weights=self.transition_probs, k=1)[0]
                    self.update_link_traffic(selected_path, ipv4_pkt)
                    path_key = '-'.join(map(str, selected_path))
                    reverse_path_key = '-'.join(map(str, selected_path[::-1]))
                    if path_key not in self.check and reverse_path_key not in self.check:
                        self.install_path_flows(selected_path, src_ip, dst_ip, src_port, dst_port)
                        self.check.add(path_key)
                        self.check.add(reverse_path_key)
                        self.logger.info(f"Selected dynamic path: {selected_path}")
        self.flood_packet(ev)

    def update_link_traffic(self, selected_path, packet):
        if (1, 2) in zip(selected_path, selected_path[1:]):
            self.link_traffic[('s2', 's4')] += packet.total_length * 8
        elif (1, 3) in zip(selected_path, selected_path[1:]):
            self.link_traffic[('s3', 's4')] += packet.total_length * 8

    def calculate_utilization(self, link, capacity):
        traffic = self.link_traffic.get(link, 0)
        utilization = traffic / (capacity * 1_000_000 * 5)
        return utilization

    def get_link_utilization(self):
        util_s2 = self.calculate_utilization(('s2', 's4'), 10)
        util_s3 = self.calculate_utilization(('s3', 's4'), 10)
        self.logger.info(f"Link s2-s4 utilization: {util_s2:.4f}")
        self.logger.info(f"Link s3-s4 utilization: {util_s3:.4f}")
        self.link_traffic[('s2', 's4')] = 0
        self.link_traffic[('s3', 's4')] = 0

    def start_periodic_utilization_display(self):
        while True:
            self.get_link_utilization()
            self.update_transition_probs()
            hub.sleep(5)

    def install_path_flows(self, path, src_ip, dst_ip, src_port, dst_port):
        for i in range(len(path) - 1):
            current_switch = path[i]
            next_switch = path[i + 1]
            datapath = self.SwitchMap.get(current_switch)
            if not datapath:
                continue
            out_port, in_port = self.d.get((current_switch, next_switch), (None, None))
            if out_port is None:
                continue
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip,
                ip_proto=6,
                tcp_src=src_port,
                tcp_dst=dst_port
            )
            actions = [parser.OFPActionOutput(out_port)]
            self.__add_flow(datapath, 10, match, actions)
        self.install_rev_path_flows(path, src_ip, dst_ip, src_port, dst_port)

    def install_rev_path_flows(self, path, src_ip, dst_ip, src_port, dst_port):
        for i in range(len(path) - 1):
            current_switch = path[i]
            next_switch = path[i + 1]
            datapath = self.SwitchMap.get(current_switch)
            if not datapath:
                continue
            out_port, in_port = self.d.get((current_switch, next_switch), (None, None))
            if out_port is None:
                continue
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=dst_ip,
                ipv4_dst=src_ip,
                ip_proto=6,
                tcp_src=dst_port,
                tcp_dst=src_port
            )
            actions = [parser.OFPActionOutput(out_port)]
            self.__add_flow(datapath, 10, match, actions)

    def flood_packet(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    def __add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    def Prober(self):
        for switch_id in [2, 3]:
            if switch_id in self.SwitchMap:
                datapath = self.SwitchMap[switch_id]
                parser = datapath.ofproto_parser
                req = parser.OFPFlowStatsRequest(datapath)
                datapath.send_msg(req)
                hub.sleep(2)
                datapath.send_msg(req)
