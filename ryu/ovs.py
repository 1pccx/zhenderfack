from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

import time
import json
import socket
import threading
import psycopg2

import snortlib
import controller_config as cfg


class SimpleSwitch13(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        "snortlib": snortlib.SnortLib
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        self.snort = kwargs["snortlib"]
        self.snort.set_config({
            "unixsock": False,
            "port": cfg.snortport
        })
        self.snort.start_socket_server()

        self.snort_alert_ips = {}
        self.dli_results = {}
        self.local_ip = self.get_local_ip()

        self.conn = None
        self.cursor = None
        self.is_connecting = False
        # Start DB connection in a background thread so it doesn't block Ryu's OpenFlow server startup!
        threading.Thread(target=self.connect_db, daemon=True).start()
        # Start DLI socket listener in a background thread to receive real-time predictions from the rack
        threading.Thread(target=self.start_dli_socket_listener, daemon=True).start()

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            self.logger.info("Automatically detected Ryu VM local IP: %s", ip)
            return ip
        except Exception:
            # Fallback to config
            return getattr(cfg, "NORMAL_SERVER_IP", "192.168.8.132")

    def connect_db(self):
        if getattr(self, 'is_connecting', False):
            return
        self.is_connecting = True
        try:
            if self.conn:
                try:
                    self.cursor.close()
                    self.conn.close()
                except Exception:
                    pass
            # Retrieve DB_PORT from config, default to 5432 if not specified
            port = getattr(cfg, "DB_PORT", 5432)
            self.conn = psycopg2.connect(
                host=cfg.DB_HOST,
                port=port,
                database=cfg.DB_NAME,
                user=cfg.DB_USER,
                password=cfg.DB_PASSWORD,
                connect_timeout=5
            )
            self.cursor = self.conn.cursor()
            self.logger.info("Successfully connected to Database %s:%s", cfg.DB_HOST, port)
        except Exception as e:
            self.logger.error("Failed to connect to Database %s - %s", cfg.DB_HOST, e)
            self.conn = None
            self.cursor = None
        finally:
            self.is_connecting = False

    def start_dli_socket_listener(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind((cfg.DLI_LISTEN_HOST, cfg.DLI_LISTEN_PORT))
            server_socket.listen(5)
            self.logger.info("DLI Socket Listener started on %s:%s", cfg.DLI_LISTEN_HOST, cfg.DLI_LISTEN_PORT)
        except Exception as e:
            self.logger.error("Failed to start DLI Socket Listener on %s:%s - %s", cfg.DLI_LISTEN_HOST, cfg.DLI_LISTEN_PORT, e)
            return

        while True:
            try:
                client_sock, client_addr = server_socket.accept()
                self.logger.info("Accepted DLI connection from %s", client_addr)
                
                # Handle connection in a separate thread so it doesn't block the listening loop
                threading.Thread(target=self.handle_dli_connection, args=(client_sock,), daemon=True).start()
            except Exception as e:
                self.logger.error("Error in DLI Socket Listener accept loop: %s", e)
                time.sleep(1)

    def handle_dli_connection(self, client_sock):
        try:
            data = client_sock.recv(1024)
            if data:
                payload = json.loads(data.decode('utf-8'))
                src_ip = payload.get("src_ip")
                result = payload.get("result") # 0 = benign, 1 = malicious
                
                if src_ip is not None and result is not None:
                    self.logger.info("Received DLI prediction for %s: result=%s", src_ip, result)
                    self.dli_results[src_ip] = (result, time.time())
                    
                    # Update local database in a thread-safe manner
                    label = 'malicious' if result == 1 else 'benign'
                    risk_level = '高' if result == 1 else '低'
                    if self.conn and self.conn.closed == 0:
                        try:
                            # Update the latest command from this IP that hasn't been labeled yet
                            sql = """
                            UPDATE incoming_commands
                            SET predicted_label = %s, risk_level = %s
                            WHERE id = (
                                SELECT id FROM incoming_commands
                                WHERE src_ip = %s AND predicted_label IS NULL
                                ORDER BY id DESC LIMIT 1
                            );
                            """
                            with self.conn.cursor() as cur:
                                cur.execute(sql, (label, risk_level, src_ip))
                            self.conn.commit()
                            self.logger.info("Updated local database with DLI result for %s", src_ip)
                        except Exception as db_err:
                            self.logger.error("Failed to update local DB with DLI prediction: %s", db_err)
                            if self.conn:
                                try:
                                    self.conn.rollback()
                                except Exception:
                                    pass
        except Exception as e:
            self.logger.error("Error handling DLI socket connection: %s", e)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def add_flow(self, datapath, priority, match, actions, idle_timeout=5):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout
        )

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def snort_alert_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.pkt)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt:
            self.snort_alert_ips[ip_pkt.src] = time.time()
            self.logger.info("SNORT ALERT from %s", ip_pkt.src)
        else:
            self.logger.info("SNORT ALERT RECEIVED")

    def insert_to_db(self, src_ip, dst_ip, command_text):
        if not self.conn or self.conn.closed != 0:
            if not getattr(self, 'is_connecting', False):
                self.logger.info("Database connection closed or invalid. Reconnecting in background...")
                threading.Thread(target=self.connect_db, daemon=True).start()
            self.logger.warning("Database connection not ready. Skipping packet log for %s -> %s", src_ip, dst_ip)
            return

        sql = """
        INSERT INTO incoming_commands
        (src_ip, dst_ip, command_text)
        VALUES (%s, %s, %s)
        """

        try:
            self.cursor.execute(
                sql,
                (src_ip, dst_ip, command_text)
            )
            self.conn.commit()
            
            # Append standard SQL INSERT format to local file for SSH pipeline transfer
            try:
                escaped_text = command_text.replace("'", "''")
                file_sql = f"INSERT INTO incoming_commands (src_ip, dst_ip, command_text) VALUES ('{src_ip}', '{dst_ip}', '{escaped_text}');\n"
                with open("/root/packets.sql", "a", encoding="utf-8") as f:
                    f.write(file_sql)
            except Exception as file_err:
                self.logger.error("Failed to write to local packets.sql file: %s", file_err)
                
        except Exception as e:
            if self.conn:
                try:
                    self.conn.rollback()
                except Exception:
                    pass
            raise e

    def get_snort_result(self, src_ip):
        now = time.time()

        if src_ip in self.snort_alert_ips:
            if now - self.snort_alert_ips[src_ip] <= cfg.SNORT_ALERT_TIMEOUT:
                return 1

        return 0

    def get_dli_result(self, src_ip):
        # 1. Check in-memory real-time DLI results first
        now = time.time()
        if src_ip in self.dli_results:
            result, timestamp = self.dli_results[src_ip]
            if now - timestamp <= cfg.DLI_RESULT_TIMEOUT:
                self.logger.info("Found real-time DLI result in memory for %s: %s", src_ip, result)
                return result, "DLI_MEMORY_CACHE"

        # 2. Fallback to database query if not found in memory
        if not self.conn or self.conn.closed != 0:
            if not getattr(self, 'is_connecting', False):
                threading.Thread(target=self.connect_db, daemon=True).start()
            return 0, "DLI_OFFLINE_FALLBACK"

        try:
            sql = """
            SELECT predicted_label FROM incoming_commands
            WHERE src_ip = %s AND predicted_label IS NOT NULL
            AND created_at >= NOW() - INTERVAL '30 seconds'
            ORDER BY id DESC LIMIT 1
            """
            with self.conn.cursor() as cur:
                cur.execute(sql, (src_ip,))
                row = cur.fetchone()
                
            if row:
                label = row[0]
                if label in ['malicious', '1', 1]:
                    return 1, "DLI_DATABASE_MATCH"
                elif label in ['benign', '0', 0]:
                    return 0, "DLI_DATABASE_MATCH"
        except Exception as e:
            self.logger.error("DB QUERY ERROR in get_dli_result: %s", e)
            if self.conn:
                try:
                    self.conn.rollback()
                except Exception:
                    pass
        return 0, "DLI_OFFLINE_FALLBACK"

    def nor_gate(self, snort_result, dli_result):
        if snort_result == 0 and dli_result == 0:
            return "SERVER"

        return "HONEYPOT"

    def packet_out(self, datapath, msg, in_port, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)

    def _get_packet_payload_text(self, msg, protocol, dst_port):
        fallback = f"{protocol} dst_port={dst_port}"
        try:
            pkt = packet.Packet(msg.data)
            if len(pkt.protocols) > 0:
                last_proto = pkt.protocols[-1]
                if isinstance(last_proto, bytes) and len(last_proto) > 0:
                    decoded_str = last_proto.decode('utf-8', errors='ignore').strip()
                    cleaned_str = "".join(c for c in decoded_str if c.isprintable() or c in "\n\r\t").strip()
                    if cleaned_str:
                        return cleaned_str[:500]
        except Exception:
            pass
        return fallback

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if not ip_pkt:
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            self.packet_out(datapath, msg, in_port, actions)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        protocol = "IP"
        dst_port = 0
        src_port = 0

        if tcp_pkt:
            protocol = "TCP"
            dst_port = tcp_pkt.dst_port
            src_port = tcp_pkt.src_port
        elif udp_pkt:
            protocol = "UDP"
            dst_port = udp_pkt.dst_port
            src_port = udp_pkt.src_port

        # Bypass redirection for external internet traffic (pings, DNS, database connects)
        # to ensure Ryu VM maintains full outbound internet access!
        is_external = dst_ip.startswith("8.8.") or dst_ip == "140.130.34.85" or src_ip == "140.130.34.85"
        
        # Bypass redirection for local management/service ports on Ryu VM (SSH, PostgreSQL, Snort Port, DLI Port)
        # We must bypass BOTH inbound packets to Ryu (check dst_port) and outbound responses from Ryu (check src_port)
        is_inbound_local = dst_ip == self.local_ip and dst_port in [22, 5432, cfg.snortport, cfg.DLI_LISTEN_PORT]
        is_outbound_local = src_ip == self.local_ip and src_port in [22, 5432, cfg.snortport, cfg.DLI_LISTEN_PORT]

        if is_external or is_inbound_local or is_outbound_local:
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self.packet_out(datapath, msg, in_port, actions)
            return

        command_text = self._get_packet_payload_text(msg, protocol, dst_port)

        try:
            self.insert_to_db(
                src_ip,
                dst_ip,
                command_text
            )
        except Exception as e:
            self.logger.error("DB ERROR: %s", e)

        snort_result = self.get_snort_result(src_ip)
        dli_result, dli_source = self.get_dli_result(src_ip)

        decision = self.nor_gate(
            snort_result,
            dli_result
        )

        if decision == "HONEYPOT":
            target_ip = cfg.HONEYPOT_IP
            target_port = cfg.HONEYPOT_PORT
        else:
            target_ip = cfg.NORMAL_SERVER_IP
            target_port = cfg.NORMAL_SERVER_PORT

        self.logger.info(
            "NOR src=%s snort=%s dli=%s [%s] decision=%s target=%s:%s",
            src_ip,
            snort_result,
            dli_result,
            dli_source,
            decision,
            target_ip,
            target_port
        )

        actions = [
            parser.OFPActionSetField(ipv4_dst=target_ip)
        ]

        if tcp_pkt:
            actions.append(
                parser.OFPActionSetField(tcp_dst=target_port)
            )

        actions.append(
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        )

        if tcp_pkt and dst_port:
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip,
                ip_proto=6,
                tcp_dst=dst_port
            )

            self.add_flow(
                datapath,
                10,
                match,
                actions,
                idle_timeout=5
            )

        self.packet_out(
            datapath,
            msg,
            in_port,
            actions
        )