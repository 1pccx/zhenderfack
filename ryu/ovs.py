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

        self.conn = None
        self.cursor = None
        self.is_connecting = False
        # Start DB connection in a background thread so it doesn't block Ryu's OpenFlow server startup!
        threading.Thread(target=self.connect_db, daemon=True).start()

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
        if not self.conn or self.conn.closed != 0:
            if not getattr(self, 'is_connecting', False):
                threading.Thread(target=self.connect_db, daemon=True).start()
            return 0

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
                if label == 'malicious':
                    return 1
                elif label == 'benign':
                    return 0
        except Exception as e:
            self.logger.error("DB QUERY ERROR in get_dli_result: %s", e)
            if self.conn:
                try:
                    self.conn.rollback()
                except Exception:
                    pass
        return 0

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
        print("PACKET IN RECEIVED")

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

        # Bypass redirection for external internet traffic (pings, DNS, database connects)
        # to ensure Ryu VM maintains full outbound internet access!
        is_external = dst_ip.startswith("8.8.") or dst_ip == "140.130.34.85" or src_ip == "140.130.34.85"
        if is_external:
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self.packet_out(datapath, msg, in_port, actions)
            return

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        protocol = "IP"
        dst_port = 0

        if tcp_pkt:
            protocol = "TCP"
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            protocol = "UDP"
            dst_port = udp_pkt.dst_port

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
        dli_result = self.get_dli_result(src_ip)

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
            "NOR src=%s snort=%s dli=%s decision=%s target=%s:%s",
            src_ip,
            snort_result,
            dli_result,
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