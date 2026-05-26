snortlib.py

import logging
import six

from ryu.lib import hub
from ryu.lib import alert
from ryu.base import app_manager
from ryu.controller import event


BUFSIZE = alert.AlertPkt._ALERTPKT_SIZE


class EventAlert(event.EventBase):
    def __init__(self, msg):
        super(EventAlert, self).__init__()
        self.msg = msg


class SnortLib(app_manager.RyuApp):

    def __init__(self):
        super(SnortLib, self).__init__()

        self.name = "snortlib"

        self.config = {
            "unixsock": False,
            "port": 51234
        }

        self.nwsock = None
        self.snortip = ""

        self._set_logger()

    def set_config(self, config):
        self.config = config

    def start_socket_server(self):
        port = self.config.get("port", 51234)

        self.logger.info(
            "Starting Snort socket server on 0.0.0.0:%s",
            port
        )

        self._start_recv_nw_sock(port)

    def _start_recv_nw_sock(self, port):

        self.nwsock = hub.socket.socket(
            hub.socket.AF_INET,
            hub.socket.SOCK_STREAM
        )

        self.nwsock.setsockopt(
            hub.socket.SOL_SOCKET,
            hub.socket.SO_REUSEADDR,
            1
        )

        self.nwsock.bind(("0.0.0.0", port))

        self.nwsock.listen(5)

        self.logger.info(
            "Network socket server listening on TCP %s",
            port
        )

        hub.spawn(self._accept_loop_nw_sock)

    def _accept_loop_nw_sock(self):

        while True:

            conn, addr = self.nwsock.accept()

            self.logger.info(
                "Connected with %s",
                addr[0]
            )

            self.snortip = addr[0]

            hub.spawn(
                self._recv_loop_nw_sock,
                conn,
                addr
            )

    def _recv_loop_nw_sock(self, conn, addr):

        buf = six.binary_type()

        while True:

            ret = conn.recv(BUFSIZE)

            if len(ret) == 0:
                self.logger.info(
                    "Disconnected from %s",
                    addr[0]
                )
                break

            buf += ret

            while len(buf) >= BUFSIZE:

                data = buf[:BUFSIZE]

                msg = alert.AlertPkt.parser(data)

                if msg:
                    self.send_event_to_observers(
                        EventAlert(msg)
                    )

                buf = buf[BUFSIZE:]

    def getsnortip(self):
        return self.snortip

    def _set_logger(self):

        self.logger.propagate = False

        hdl = logging.StreamHandler()

        fmt_str = '[snort][%(levelname)s] %(message)s'

        hdl.setFormatter(
            logging.Formatter(fmt_str)
        )

        self.logger.addHandler(hdl)

        self.logger.setLevel(logging.INFO)