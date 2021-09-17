from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
from ryu.lib import hub
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event

from collections import defaultdict
from operator import itemgetter
from requests import get
from subprocess import check_output

import logging
import socket
import shlex
import re
import copy
import timeit
import os
import random
import time
import math
import queue2 as Q

# Cisco Reference bandwidth = 100 Mbps
REFERENCE_BW = 100000000

DEFAULT_BW = 100000000

MAX_PATHS = 5

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.switches = defaultdict(dict)
        self.hosts = {}
	self.routing = defaultdict(lambda: defaultdict(lambda: 0))
	self.inc = defaultdict(lambda: defaultdict(lambda: REFERENCE_BW))
	self.util = defaultdict(lambda: defaultdict(lambda: 0))
        self.multipath_group_ids = {}
	self.group_flow = defaultdict(dict)
        self.group_ids = []
	self.monitor = []
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))
        self.collector = '127.0.0.1'
	self.sleeptime = 5

    # Sflow Function
    #def getIfInfo(self,ip):
        '''
        Get interface name of ip address (collector)
        '''
        #s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #s.connect((ip, 0))
        #ip = s.getsockname()[0]
        #ifconfig = check_output(['ifconfig'])
        #ifs = re.findall(r'^(\S+).*?inet (\S+).*?', ifconfig, re.S | re.M)
        #for entry in ifs:
         #   if entry[1] == ip:
          #      return entry

    def init_sflow(self):
        '''
        Initialise sFlow for monitoring traffic
        '''
        cmd = shlex.split('ip link show')
        out = check_output(cmd)
        info = re.findall('(\d+): ((s[0-9]+)-eth([0-9]+))', out)

        #sflow = 'ovs-vsctl -- --id=@sflow create sflow agent=%s target=\\"%s\\" sampling=%s polling=%s --' % (
         #   ifname, collector, sampling, polling)

        for ifindex, ifname, switch, port in info:
            if int(switch[1:]) in self.switches:
                self.switches[int(switch[1:])]['ports'][int(port)] = {
                    'ifindex': ifindex,
                    'ifname': ifname,
                    'bandwidth': 0
                }
                #sflow += ' -- set bridge %s sflow=@sflow' % switch

        #print sflow
        # os.system('echo %s|sudo -S %s' % (sudoPassword, sflow))
        #os.system(sflow)

        hub.spawn_after(0.1, self.monitor_inc)

    def monitor_inc(self):
        '''
        Measure outgoing traffic per second for all switch ports
        '''
	print "monitored"
        while True:
            try:
                for (src, first_port, dst, last_port, pw, ip_src, ip_dst) in self.monitor:
                    url1 = 'http://' + self.collector + ':8008/metric/' + \
                              self.collector + '/' + self.switches[src]['ports'][first_port]['ifindex'] + \
                              '.ifinoctets/json'
                    r1 = get(url1)
                    response1 = r1.json()
                    url2 = 'http://' + self.collector + ':8008/metric/' + \
                              self.collector + '/' + self.switches[dst]['ports'][last_port]['ifindex'] + \
                              '.ifinoctets/json'
                    r2 = get(url2)
                    response2 = r2.json()
		    self.inc[first_port][last_port] = max((response1[0]['metricValue'] * 8),(response2[0]['metricValue'] * 8))
		    #print "incoming traffic ",src,first_port," ",dst,last_port," is ",self.inc[first_port][last_port]
                    try:
                        #update
			update = 65535
			inc_before = self.inc[first_port][last_port]
			dp = self.datapath_list[src]
			group_id = self.multipath_group_ids[dp, first_port, last_port]
			out_ports = self.group_flow[group_id]
            		ofp = dp.ofproto
            		ofp_parser = dp.ofproto_parser
			traffic_jump = abs(self.inc[first_port][last_port] - inc_before)
			most_free_port = None
			max_free = 0
			pw_sum = 0
			free_band_sum = 0
			for port,weight in out_ports:
				pw_sum += weight
				url = 'http://' + self.collector + ':8008/metric/' + \
                        	      self.collector + '/' + self.switches[src]['ports'][port]['ifindex'] + \
                        	      '.ifoututilization/json'
				r = get(url)
                    		response = r.json()
				#print dp,port," utilization is ",response[0]['metricValue']
				self.util[port] = (response[0]['metricValue'] * weight)
				free_band = weight - self.util[port]
				free_band_sum += free_band
				if max_free < free_band:
					max_free = free_band
					most_free_port = port
	
			if self.inc[first_port][last_port] > (pw[0] * 0.8):
				if self.routing[ip_src][ip_dst] == 0:
					update = 1
				#elif traffic_jump > 10000000:
				#	update = 1
				#elif traffic_jump < 10000000:
				#	update = 65535
				#	if max_free > 10000000:
				#		update = 1 
			#elif self.routing[ip_src][ip_dst] == 1:
			#	update = 0
				#self.sleeptime = 3
			#elif self.sleeptime > 10:
			#	update = 65535
			#	print "5 seconds idle"
			#	self.sleeptime = 3
			elif self.inc[first_port][last_port] < max_free:
				update = 0
				if self.routing[ip_src][ip_dst] == 0:
				#	self.sleeptime = 3
					update = 65535
				#else :
				#	self.sleeptime = 3
			elif self.inc[first_port][last_port] > max_free:
				update = 1
				if self.routing[ip_src][ip_dst] == 1:
				#	self.sleeptime = 3
					update = 65535
				#else :
				#	self.sleeptime = 3
 
			#print "group id:",first_port,last_port,group_id
                        #print "incoming traffic: ",self.inc
			buckets = []
			if update == 1:
				print "update weight for multipath routing"
				i = 0
				for port,weight in out_ports:
					if self.routing[ip_src][ip_dst] == 1:
                        			bucket_weight = (float(weight - self.util[port])/float(free_band_sum)) * 10
					else : 
						bucket_weight = (float(weight)/float(pw_sum)) * 10
						#bucket_weight = (float(weight - self.util[port])/float(free_band_sum)) * 10
					if bucket_weight < 1:
						bucket_weight = 1
                        		bucket_action = [ofp_parser.OFPActionOutput(port)]
                        		buckets.append(ofp_parser.OFPBucket(weight=bucket_weight,watch_port=port,
						watch_group=ofp.OFPG_ANY,
						actions=bucket_action)
					)
					print src, " port ",port," bucket weight is ",bucket_weight," [",ip_dst,"]"
				self.group_flow[group_id] = out_ports
                        	req = ofp_parser.OFPGroupMod(dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,group_id, buckets)
                        	dp.send_msg(req)
				self.routing[ip_src][ip_dst] = 1					

			elif update == 0:
				print "update weight for singlepath routing"
				for port,pw in out_ports:
					bucket_weight = 0
					if port == most_free_port:
						bucket_weight = 65535
					bucket_action = [ofp_parser.OFPActionOutput(port)]
                        		buckets.append(ofp_parser.OFPBucket(weight=bucket_weight,watch_port=port,
						watch_group=ofp.OFPG_ANY,
						actions=bucket_action)
					)
				self.group_flow[group_id] = out_ports
                        	req = ofp_parser.OFPGroupMod(dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,group_id, buckets)
                        	dp.send_msg(req)
				self.routing[ip_src][ip_dst] = 0	
				#print "update weight for singlepath routing"
			#else:
				#print "no update between s",src," port ",first_port," s ",dst," port ",last_port

                    except KeyError:
                        pass
                          #print switch,thr[switch]
            except RuntimeError:
                pass
            hub.sleep(3)
    # End Sflow

    def convert(self, val):
        lookup = {'G': 1000000000, 'M': 1000000}
        try:
            unit = val[-5]
            number = int(val[:-5])
            if unit in lookup:
                return lookup[unit] * number
        except ValueError:
            pass
        except IndexError:
            print val

    # Dijkstra
    def minimum_distance(self, distance, Q):
        min = float('Inf')
        node = 0
        for v in Q:
            if distance[v] < min:
                min = distance[v]
                node = v
        return node

    def dijkstra(self, graph, src, dst):
        # Dijkstra's algorithm
        # print "get_path is called, src=", src, " dst=", dst
        if src not in graph.keys():
            return []
        if dst not in graph.keys():
            return []

        distance = {}
        previous = {}
	#print "graph node ",graph.keys()

        for dpid in graph.keys():
            distance[dpid] = float('Inf')
            previous[dpid] = None

        distance[src] = 0
        Q = set(graph.keys())
        #print "Q=", Q

        while len(Q) > 0:
            u = self.minimum_distance(distance, Q)
            try:
                Q.remove(u)
            except KeyError:
                Q.clear()

            for p in graph.keys():
                if graph[u].has_key(p):
                    # w = 1
                    w = self.get_link_cost(u, p)
                    if distance[u] + w < distance[p]:
                        distance[p] = distance[u] + w
                        previous[p] = u
	
        r = []
        p = dst
        r.append(p)
        q = previous[p]
        while q is not None:
            if q == src:
                r.append(q)
                break
            p = q
            r.append(p)
            q = previous[p]

        r.reverse()
        if src == dst:
            path = [src]
        else:
            path = r

        return path
    # End Dijkstra

    def get_paths(self, src, dst):
        time1 = time.time()
        paths = []
        graph = copy.deepcopy(self.adjacency)
        path = self.dijkstra(graph, src, dst)
        #print "graph nodes ", graph.keys()
        while path:
            paths.append(path)
                # Remove link from graph
            for i in range(len(path) - 1):
                del graph[path[i]][path[i + 1]]
                del graph[path[i + 1]][path[i]]

                # Remove switch if there is no link anymore
            for i in range(len(path)):
                if not graph[path[i]]:
                    del graph[path[i]]
            path = self.dijkstra(graph, src, dst)
        time2 = time.time() - time1
        #print "Available paths from ", src, " to ", dst, " : ", paths
        print "Path Execution Time : ", time2
        return  paths

    def get_link_cost(self, s1, s2):
        '''
        Get the link cost between two switches 
        '''
        e1 = self.adjacency[s1][s2]
        e2 = self.adjacency[s2][s1]
        bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
        ew = float(REFERENCE_BW/bl)
        return ew

    def get_path_min_bandwidth(self,path):
        band = REFERENCE_BW
        for i in range(len(path) - 1):
            e1 = self.adjacency[path[i]][path[i+1]]
            e2 = self.adjacency[path[i+1]][path[i]]
            band = min(self.bandwidths[path[i]][e1], self.bandwidths[path[i+1]][e2], band)
        return band

    def add_ports_to_paths(self, paths, first_port, last_port):
        '''
        Add the ports that connects the switches for all paths
        '''
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.adjacency[s1][s2]
                p[s1] = (in_port, out_port)
                in_port = self.adjacency[s2][s1]
            p[path[-1]] = (in_port, last_port)
            paths_p.append(p)
        return paths_p

    def generate_openflow_gid(self):
        '''
        Returns a random OpenFlow group id
        '''
        n = random.randint(0, 2**32)
        while n in self.group_ids:
            n = random.randint(0, 2**32)
        return n

    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        computation_start = time.time()
        paths = self.get_paths(src, dst)
	traffic = min(self.bandwidths[src][first_port],self.bandwidths[dst][last_port])
	sum_of_pw = 0
        pw = []
        for path in paths:
            pw.append(self.get_path_min_bandwidth(path))
	    sum_of_pw += self.get_path_min_bandwidth(path)
            print path, "minimal path bandwidth = ", pw[len(pw) - 1]
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        switches_in_paths = set().union(*paths)
	if (src, first_port, dst, last_port, pw, ip_src, ip_dst) not in self.monitor:
		self.monitor.append([src, first_port, dst, last_port, pw, ip_src, ip_dst])
 
        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = defaultdict(list)
            actions = []
            i = 0

            for path in paths_with_ports:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    if (out_port, pw[i]) not in ports[in_port]:
                        ports[in_port].append((out_port, pw[i]))
                i += 1

            for in_port in ports:

                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800,
		    #ip_proto=6, 
                    ipv4_dst=ip_dst
                )
		match_udp = ofp_parser.OFPMatch(
                    eth_type=0x0800,
	  	    ip_proto=17,
                    ipv4_dst=ip_dst,
		    #udp_dst=80
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )

                out_ports = ports[in_port]
                # print out_ports 

                if len(out_ports) > 1:
                    group_id = None
                    group_new = False

                    if (dp, first_port, last_port) not in self.multipath_group_ids:
                        group_new = True
                        self.multipath_group_ids[
                            dp, first_port, last_port] = self.generate_openflow_gid()
                    group_id = self.multipath_group_ids[dp, first_port, last_port]

                    buckets = []
		    self.routing[ip_src][ip_dst] = 1
                    # print "node at ",node," out ports : ",out_ports
                    for port, weight in out_ports:
                        bucket_weight = (float(weight)/float(sum_of_pw)) * 10
			if bucket_weight < 1:
				bucket_weight = 1
			if self.routing[ip_src][ip_dst] == 0:
				bucket_weight = 0
                        #bucket_weight = int(round((1 - weight/sum_of_pw) * 10))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                watch_port=port,
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )
			if traffic < pw[0] * 0.8:
				self.routing[ip_src][ip_dst] = 0


                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        dp.send_msg(req)
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                            group_id, buckets)
                        dp.send_msg(req)

		    self.group_flow[group_id] = out_ports
                    actions = [ofp_parser.OFPActionGroup(group_id)]

                    self.add_flow(dp, 2, match_ip, actions)
                    self.add_flow(dp, 3, match_udp, actions)
                    self.add_flow(dp, 1, match_arp, actions)

                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]

                    self.add_flow(dp, 2, match_ip, actions)
                    self.add_flow(dp, 3, match_udp, actions)
                    self.add_flow(dp, 1, match_arp, actions)
        print "Path installation finished in ", time.time() - computation_start 
        return paths_with_ports[0][src][1]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # print "Adding flow ", match, actions
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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        print "switch_features_handler is called"
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        tc = "tc class show dev "
        awk = " | awk '{print $7}'"
        for p in ev.msg.body:
            inf = p.name
            #link_bandwidth_str = os.popen(tc + int + awk).read()
            link_bandwidth_str = os.popen(tc + inf + awk).read()
            link_bandwidth = self.convert(link_bandwidth_str)
            self.bandwidths[switch.id][p.port_no] = link_bandwidth

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if arp_pkt:
            # print dpid, pkt
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                    self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse

        # print pkt

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser

        if switch.id not in self.switches:
            self.switches[switch.id]['ports'] = defaultdict(dict)
            self.datapath_list[switch.id] = switch

            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)
	    self.init_sflow()

        #if self.switches:
            #(ifname, agent) = self.getIfInfo(self.collector)
            #ifname = ifname.replace(":","")
            #logging.getLogger("requests").setLevel(logging.WARNING)
            #logging.getLogger("urllib3").setLevel(logging.WARNING)
            #self.init_sflow(ifname, self.collector, 10, 10)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        print ev
        switch = ev.switch.dp.id
        if switch in self.switches:
            self.switches.pop(switch)
            del self.datapath_list[switch]
            del self.adjacency[switch]

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        # Exception handling if switch already deleted
        try:
            del self.adjacency[s1.dpid][s2.dpid]
            del self.adjacency[s2.dpid][s1.dpid]
        except KeyError:
            pass

