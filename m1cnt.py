from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, icmp ,in_proto ,ether_types
import networkx as nx
import hashlib
import threading
from ryu.lib import hub
import time
class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    BytesArray = [0, 0]
    TimeArray = [0, 0]
    dic = {}
    index = 0
    P_S1_S1 = 0.1  
    P_S1_S2 = 0.9
    P_S2_S2 = 0.8  
    P_S2_S1 = 0.2  
    current_state = 'S1' 
    u1 = 0 
    u2 = 0
    f = 1
    l  = [(5001 , 5001) , (5002 , 5001)]
    
    prt_path = {(5001 , 5001):[1,3,4]}

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.network = nx.Graph()
        self.mac_to_port = {}  # MAC address table for each switch
        self.mac_to_dpid = {}  # MAC-to-switch mapping for hosts
        self.link_traffic = {  # Dictionary to track link traffic (bytes)
            ('s2', 's4'): 0,
            ('s3', 's4'): 0
        }
        self.one = 0
        self.two = 0
        self.d = {
            (1, 2): [2, 1],
            (1, 3): [3, 1],
            (2, 4): [2, 1],
            (3, 4): [2, 2],
        }
        self.p = [[1, 2, 4], [1, 3, 4]]
        self.check = {}
        self.SwitchMap = {}  # datapath id -> datapath
        self.logger.info("Initializing controller...")

        # Manually define the topology graph
        self.define_topology()
        
        # Start background thread
        self.daemon_thread = threading.Thread(target=self.background_task, daemon=True)
        self.daemon_thread.start()
        
        self.thread1 = threading.Thread(target=self.update_state, daemon=True)
        self.thread1.start()

        # Start periodic link utilization display
        self.start_periodic_utilization_display()
        # self.monitor_thread = hub.spawn(self._monitor)

        
    def _monitor(self):
        while True:
            hub.sleep(10)
            self.Prober()

    def define_topology(self):
        """Manually define the network topology."""
        # Add edges between switches with ports for both directions
        self.network.add_edges_from([
            (1, 2, {'src_port': 2, 'dst_port': 1}),
            (1, 3, {'src_port': 3, 'dst_port': 1}),
            (2, 4, {'src_port': 2, 'dst_port': 1}),
            (3, 4, {'src_port': 2, 'dst_port': 2}),
        ])
        self.logger.info(f"Manually defined topology: {self.network.edges(data=True)}")

    def calculate_ecmp_paths(self, src, dst):
        """Calculate ECMP paths between two switches."""
        try:
            paths = list(nx.all_shortest_paths(self.network, source=src, target=dst))
            return paths
        except nx.NetworkXNoPath:
            self.logger.error(f"No path between {src} and {dst}")
            return []

    def hash_flow(self, src_ip, src_port, dst_ip, dst_port):
        """Generate a hash based on the 4-tuple."""
        flow_str = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        return int(hashlib.md5(flow_str.encode()).hexdigest(), 16)
    
    def compute_transition_probs(self, throughput_path_1, throughput_path_2):
        # Compute transition probabilities based on throughput
        total_throughput = throughput_path_1 + throughput_path_2
        if total_throughput ==0 :
            #print("total_throughput - " ,total_throughput)
            return 0 ,0 ,0, 0
        P_S1_S2 = throughput_path_1 / total_throughput  # Probability of staying on Path 1
        P_S1_S1 = 1 - P_S1_S2  # Probability of switching to Path 2
        P_S2_S1 = throughput_path_2 / total_throughput  # Probability of staying on Path 2
        P_S2_S2 = 1 - P_S2_S1  # Probability of switching to Path 1
        #print (f"upadated - P_S1_S1 {P_S1_S1}, P_S1_S2 {P_S1_S2}, P_S2_S2 {P_S2_S2}, P_S2_S1 {P_S2_S1}")
        return P_S1_S1, P_S1_S2, P_S2_S2, P_S2_S1
    
    
    
    def update_state(self):
        # Measure throughput of both paths
        while True:
            time.sleep(3)
            throughput_path_1, throughput_path_2 = self.u1 , self.u2

            # Compute the transition probabilities
            P_S1_S1, P_S1_S2, P_S2_S2, P_S2_S1 = self.compute_transition_probs(throughput_path_1, throughput_path_2)
            print(P_S1_S1, P_S1_S2, P_S2_S2, P_S2_S1 )
            # Decide transition based on the current state and transition probabilities
            self.f = 1
            if self.current_state == 'S1':  # Path 1 is active
                if P_S1_S1 < self.P_S1_S1:
                    print(f"Stay on Path 1 (S1) ")
                else:
                    self.current_state = 'S2'
                    print(f"Switch to Path 2 (S2) ")
                    self.up_fl("S1" ,self.current_state)
                    
            elif self.current_state == 'S2':  # Path 2 is active
                if P_S2_S2 < self.P_S2_S2:
                    print(f"Stay on Path 2 (S2) ")
                else:
                    self.current_state = 'S1'
                    self.up_fl("S2" ,self.current_state)
                    print(f"Switch to Path 1 (S1)")

      

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        
        
        """Install default rule to send unmatched packets to the controller."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        switch_no = datapath.id
        self.SwitchMap[switch_no] = datapath
        self.__add_flow(datapath, 0, match, actions)
        self.logger.info(f"Default flow installed for switch {datapath.id}")
        
       
        
        
        if datapath.id == 1:
            match = parser.OFPMatch(in_port=2, ip_proto=in_proto.IPPROTO_TCP, eth_type=ether_types.ETH_TYPE_IP)
            out_port = 1
            actions = [parser.OFPActionOutput(out_port)]
            self.__add_flow(datapath, 10, match, actions)
            
            match = parser.OFPMatch(in_port=3, ip_proto=in_proto.IPPROTO_TCP, eth_type=ether_types.ETH_TYPE_IP)
            out_port = 1
            actions = [parser.OFPActionOutput(out_port)]
            self.__add_flow(datapath, 10, match, actions)
            
        if datapath.id == 4:
            match = parser.OFPMatch(in_port=2, ip_proto=in_proto.IPPROTO_TCP, eth_type=ether_types.ETH_TYPE_IP)
            out_port = 3
            actions = [parser.OFPActionOutput(out_port)]
            self.__add_flow(datapath, 10, match, actions)
            
            match = parser.OFPMatch(in_port=1, ip_proto=in_proto.IPPROTO_TCP, eth_type=ether_types.ETH_TYPE_IP)
            out_port = 3
            actions = [parser.OFPActionOutput(out_port)]
            self.__add_flow(datapath, 10, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle Packet-In events."""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        # Ensure that the packet is an Ethernet frame
        eth = pkt.get_protocols(ethernet.ethernet)
        if not eth:
            self.logger.info("Not an Ethernet packet, ignoring.")
            return  # If it's not an Ethernet packet, we simply return

        eth = eth[0]  # Extract the first Ethernet frame

        # Learn the MAC address
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][eth.src] = in_port
        self.mac_to_dpid[eth.src] = datapath.id

        # Now that it's an Ethernet frame, check for higher-layer protocols
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            src_ip, dst_ip = ipv4_pkt.src, ipv4_pkt.dst

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                src_port, dst_port = tcp_pkt.src_port, tcp_pkt.dst_port
                

                # If all necessary fields are present, handle the packet directly
                if all([src_ip, dst_ip, src_port, dst_port]):
                    # Calculate ECMP paths and hash the flow to decide the path
                    paths = self.calculate_ecmp_paths(1, 4)  # Example: paths between s2 and s4
                    path = self.hash_flow(src_ip, src_port, dst_ip, dst_port) % len(paths)
                    selected_path = paths[path]
                    self.p = paths[path]
                    
                    self.prt_path[(src_port,dst_port)] = selected_path
                    self.update_link_traffic(selected_path, ipv4_pkt)
                    self.install_path_flows(selected_path, src_ip, dst_ip, src_port, dst_port,datapath)
                    
                    # Update link traffic 
                    

                    # Process the packet (install flow, forward, etc.)
                    actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
                    
                    if (src_port , dst_port) not in self.dic:
                        self.logger.info(f"TCP packet: {src_port} -> {dst_port}")
                        
                        self.logger.info(f"Selected ECMP path: {selected_path} - total path {len(paths)}")
                        self.dic[(src_port , dst_port)] = 1
                    
                    	
        self.flood_packet(ev)
                        


        # If missing fields or not matching, flood the packet
        

    def update_link_traffic(self, selected_path, packet):
        """Update link traffic based on selected path."""
        if 2 in selected_path:
            self.link_traffic[('s2', 's4')] += packet.total_length * 8
        elif 3 in selected_path:
            self.link_traffic[('s3', 's4')] += packet.total_length * 8 

    def calculate_utilization(self, link, capacity):
        """Calculate link utilization based on traffic and link capacity."""
        traffic = self.link_traffic.get(link)
        utilization = traffic / (capacity*2000)  # Simplified formula
        return utilization

    def get_link_utilization(self):
        """Print the utilization of s2-s4 and s3-s4."""
        s2_s4_capacity = 10  # Assume capacity (adjust as needed)
        s3_s4_capacity = 10
        s2_s4_utilization = self.calculate_utilization(('s2', 's4'), s2_s4_capacity)
        s3_s4_utilization = self.calculate_utilization(('s3', 's4'), s3_s4_capacity)
        if s2_s4_utilization != 0:
            self.logger.info(f"(s2-s4): {s2_s4_utilization/10 :.2f}")
            self.u1 = s2_s4_utilization / 1000
        if s3_s4_utilization != 0:
            self.logger.info(f"(s3-s4): {s3_s4_utilization / 10:.2f}")
            self.u2 = s2_s4_utilization / 100
            
            

    def start_periodic_utilization_display(self):
        """Start a periodic display of link utilization every 5 seconds."""
        def display_utilization():
            while True:
                self.get_link_utilization()
                time.sleep(5)  # Sleep for 1 second before the next update
        
        # Start the periodic display in a new thread
        threading.Thread(target=display_utilization, daemon=True).start()

    def install_path_flows(self, path, src_ip, dst_ip, src_port, dst_port,datapath):
        if '-'.join(map(str, path)) in self.check :
            return 
        
        """
        Install flow rules along the selected path for the given flow.
        Args:
            path: List of switches in the selected path.
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            src_port: Source TCP port.
            dst_port: Destination TCP port.
        """
        for i in range(len(path) - 1):
            current_switch = path[i]
            next_switch = path[i + 1]

            # Get the datapath for the current switch
            print(type(current_switch))
            
            if not datapath:
                self.logger.error(f"Datapath for switch {current_switch} not found!")
                continue

            # Get ports from self.d
            ports = self.d.get((current_switch, next_switch))
            if not ports:
                self.logger.error(f"No port mapping for switch {current_switch} -> {next_switch}")
                continue

            out_port, in_port = ports  # Ports for current to next switch
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Match fields for the flow
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_src=dst_ip,
                ipv4_dst=src_ip,
                ip_proto=6,  # TCP
                tcp_src=dst_port,
                tcp_dst=src_port
            )

            # Actions to forward the packet to the next switch
            actions = [parser.OFPActionOutput(out_port)]

            # Add flow to the switch
            self.__add_flow(datapath, priority=10, match=match, actions=actions)
            self.logger.info(f"Flow added: Switch {current_switch}, Match {match}, Out Port {out_port}")
            
            self.check['-'.join(map(str, path))] = 1
            self.install_rev_path_flows( path, src_ip, dst_ip, src_port, dst_port,datapath)
            
    def install_rev_path_flows(self, path, src_ip, dst_ip, src_port, dst_port,datapath):
        
        """
        Install flow rules along the selected path for the given flow.
        Args:
            path: List of switches in the selected path.
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            src_port: Source TCP port.
            dst_port: Destination TCP port.
        """
        for i in range(len(path) - 1):
            current_switch = path[i]
            next_switch = path[i + 1]

            # Get the datapath for the current switch
            print(type(current_switch))
            
            if not datapath:
                self.logger.error(f"Datapath for switch {current_switch} not found!")
                continue

            # Get ports from self.d
            ports = self.d.get((current_switch, next_switch))
            if not ports:
                self.logger.error(f"No port mapping for switch {current_switch} -> {next_switch}")
                continue

            out_port, in_port = ports  # Ports for current to next switch
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Match fields for the flow
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_src=src_ip,
                ipv4_dst= dst_ip,
                ip_proto=6,  # TCP
                tcp_src=src_port,
                tcp_dst= dst_port
            )

            # Actions to forward the packet to the next switch
            actions = [parser.OFPActionOutput(out_port)]

            # Add flow to the switch
            self.__add_flow(datapath, priority=10, match=match, actions=actions)
            self.logger.info(f"Flow added: Switch {current_switch}, Match {match}, Out Port {out_port}")
            
    def background_task(self):
        while True:
            time.sleep(20)
            self.link_traffic[('s2', 's4')] = 645
            self.link_traffic[('s3', 's4')] = 546
            self.dic = {}
        

    def flood_packet(self, ev):
        """Flood the packet to all ports except the incoming port."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser
        in_port = msg.match['in_port']
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def __add_flow(self, datapath, priority, match, actions):
        """Add a flow rule to the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
        
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        msg = ev.msg
        body = msg.body

        for stat in body:
            if 'in_port' in stat.match and stat.match['in_port'] == 1:
                
                self.BytesArray[self.index] += stat.byte_count
                self.TimeArray[self.index] = max(stat.duration_sec, self.TimeArray[self.index])
        
        self.index=(self.index+1)%2

        if self.index==0:
            bytes=self.BytesArray[1]-self.BytesArray[0]
            
            time=self.TimeArray[1]-self.TimeArray[0]
            
            throughput=bytes/(time*100000) # in terms of 0.1 MBps 
            self.BytesArray[0] = self.BytesArray[1] = self.TimeArray[0] = self.TimeArray[1] = 0
            
    def Prober(self):
        if 3 not in self.SwitchMap:
            return
        datapath = self.SwitchMap[3]
        parser  = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        time.sleep(5)
        datapath.send_msg(req)
        
        
        if 2 not in self.SwitchMap:
            return
        datapath = self.SwitchMap[2]
        parser  = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        time.sleep(5)
        datapath.send_msg(req)
        
    def update_flows(self, selected_path, src_ip, dst_ip, src_port, dst_port,datapath,path):
        time.sleep(5)
        print("updating the flow rules")
        if path == 0 :
            path = 1
        else:
            path = 0
        path = self.p[path]

        for i in range(len(path) - 1):
            current_switch = path[i]
            next_switch = path[i + 1]

            # Get the datapath for the current switch
            #print(type(current_switch))
            
            if not datapath:
                self.logger.error(f"Datapath for switch {current_switch} not found!")
                continue

            # Get ports from self.d
            ports = self.d.get((current_switch, next_switch))
            if not ports:
                self.logger.error(f"No port mapping for switch {current_switch} -> {next_switch}")
                continue

            out_port, in_port = ports  # Ports for current to next switch
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Match fields for the flow
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_src=src_ip,
                ipv4_dst= dst_ip,
                ip_proto=6,  # TCP
                tcp_src=src_port,
                tcp_dst= dst_port
            )

            # Actions to forward the packet to the next switch
            actions = [parser.OFPActionOutput(out_port)]

            # Add flow to the switch
            self.__add_flow(datapath, priority=10, match=match, actions=actions)
            self.logger.info(f"Flow updated: Switch {current_switch}, Match {match}, Out Port {out_port}") 
            self.install_rev_path_flows( path, src_ip, dst_ip, src_port, dst_port,datapath)   
    
    def up_fl (self,os ,cs ):
        #self.task()
        print('updating flows...................................................' ,self.prt_path)
        if os == 'S1' and cs == 'S2':
            for j in self.prt_path:
                path = [1 , 3 , 4]
                for i in range(len(path) - 1):
                    current_switch = path[i]
                    next_switch = path[i + 1]
                    
                    
                    ports = self.d.get((current_switch, next_switch))
                    if not ports:
                        self.logger.error(f"No port mapping for switch {current_switch} -> {next_switch}")
                        continue
                    
                    src_port ,dst_port = j # Ports for current to next switch
                    datapath = self.SwitchMap[current_switch]
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser
                    out_port, in_port = ports

                    # Match fields for the flow
                    match = parser.OFPMatch(
                        eth_type=0x0800,  # IPv4
                        ipv4_src= '10.0.0.1',
                        ipv4_dst= '10.0.0.2',
                        ip_proto=6,  # TCP
                        tcp_src=src_port,
                        tcp_dst= dst_port
                    )

                    # Actions to forward the packet to the next switch
                    actions = [parser.OFPActionOutput(out_port)]

                    # Add flow to the switch
                    self.__add_flow(datapath, priority=10, match=match, actions=actions)
                    self.logger.info(f"Flow updated: Switch {current_switch}, Match {match}, Out Port {out_port}")

        if os == 'S1' and cs == 'S2':
            for j in self.prt_path:
                path = [1 , 2, 4]
                for i in range(len(path) - 1):
                    current_switch = path[i]
                    next_switch = path[i + 1]
                    print( i , '..................................................................')
                    ports = self.d.get((current_switch, next_switch))
                    if not ports:
                        self.logger.error(f"No port mapping for switch {current_switch} -> {next_switch}")
                        continue
                    
                    src_port ,dst_port = j  # Ports for current to next switch
                    datapath = self.SwitchMap[current_switch]
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser
                    out_port, in_port = ports

                    # Match fields for the flow
                    match = parser.OFPMatch(
                        eth_type=0x0800,  # IPv4
                        ipv4_src= '10.0.0.1',
                        ipv4_dst= '10.0.0.2',
                        ip_proto=6,  # TCP
                        tcp_src=src_port,
                        tcp_dst= dst_port
                    )

                    # Actions to forward the packet to the next switch
                    actions = [parser.OFPActionOutput(out_port)]

                    # Add flow to the switch
                    self.__add_flow(datapath, priority=10, match=match, actions=actions)
                    self.logger.info(f"Flow updated: Switch {current_switch}, Match {match}, Out Port {out_port}")
        