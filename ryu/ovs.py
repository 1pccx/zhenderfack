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

        self.conn = None
        self.cursor = None
        self.is_connecting = False
        self.connect_db()

        self.start_dli_listener_thread()

        self.logger.info("Ryu + Snort + DB + DLI Socket + NOR started")
        self.logger.info(
            "DLI_MODE=%s DLI_FIXED_RESULT=%s",
            getattr(cfg, "DLI_MODE", "socket"),
            getattr(cfg, "DLI_FIXED_RESULT", "N/A")
        )

    def connect_db(self):
        self.is_connecting = True

        try:
            self.conn = psycopg2.connect(
                host=cfg.DB_HOST,
                port=cfg.DB_PORT,
                database=cfg.DB_NAME,
                user=cfg.DB_USER,
                password=cfg.DB_PASSWORD,
                connect_timeout=3
            )

            self.cursor = self.conn.cursor()

            self.logger.info(
                "Connected to PostgreSQL %s:%s/%s",
                cfg.DB_HOST,
                cfg.DB_PORT,
                cfg.DB_NAME
            )

        except Exception as e:
            self.conn = None
            self.cursor = None
            self.logger.error("PostgreSQL connect failed: %s", e)

        finally:
            self.is_connecting = False

    def start_dli_listener_thread(self):
        t = threading.Thread(
            target=self.start_dli_listener,
            daemon=True
        )
        t.start()

    def start_dli_listener(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((cfg.DLI_LISTEN_HOST, cfg.DLI_LISTEN_PORT))
        server.listen(5)

        print(f"[DLI] Listener started on {cfg.DLI_LISTEN_HOST}:{cfg.DLI_LISTEN_PORT}")

        while True:
            conn, addr = server.accept()

            try:
                data = conn.recv(4096).decode().strip()

                if not data:
                    conn.close()
                    continue

                result = json.loads(data)

                src_ip = result.get("src_ip")
                dli_result = int(result.get("result", 0))

                if src_ip:
                    self.dli_results[src_ip] = {
                        "result": dli_result,
                        "time": time.time()
                    }

                    print(
                        f"[DLI] Result from {addr}: "
                        f"src_ip={src_ip}, result={dli_result}"
                    )

            except Exception as e:
                print(f"[DLI] Socket error: {e}")

            finally:
                conn.close()

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
            if not getattr(self, "is_connecting", False):
                self.logger.info("Database connection closed or invalid. Reconnecting in background...")
                threading.Thread(target=self.connect_db, daemon=True).start()

            self.logger.warning(
                "Database connection not ready. Skipping packet log for %s -> %s",
                src_ip,
                dst_ip
            )
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

            print(
                f"[DB INSERT] src_ip={src_ip}, "
                f"dst_ip={dst_ip}, command_text={command_text}"
            )

        except Exception as e:
            if self.conn:
                try:
                    self.conn.rollback()
                except Exception:
                    pass

            self.logger.error("DB INSERT ERROR: %s", e)

            if not getattr(self, "is_connecting", False):
                threading.Thread(target=self.connect_db, daemon=True).start()

    def get_snort_result(self, src_ip):
        now = time.time()

        if src_ip in self.snort_alert_ips:
            if now - self.snort_alert_ips[src_ip] <= cfg.SNORT_ALERT_TIMEOUT:
                return 1

        return 0

    def get_dli_result(self, src_ip):
        if getattr(cfg, "DLI_MODE", "socket") == "fixed":
            return int(cfg.DLI_FIXED_RESULT)

        now = time.time()

        if src_ip in self.dli_results:
            item = self.dli_results[src_ip]

            if now - item["time"] <= cfg.DLI_RESULT_TIMEOUT:
                return int(item["result"])

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
            print("[SKIP] non-IPv4 packet")
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            self.packet_out(datapath, msg, in_port, actions)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

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

        command_text = f"{protocol} dst_port={dst_port}"

        self.insert_to_db(
            src_ip,
            dst_ip,
            command_text
        )

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