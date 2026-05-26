snortport = 51234

controller_port = 6653
controller_ip = "127.0.0.1"

# Ryu 透過 SSH tunnel 連機架 DB
# ssh -L 15432:127.0.0.1:5432
DB_HOST = "127.0.0.1"
DB_PORT = 15432
DB_NAME = "security_db"
DB_USER = "data_user"
DB_PASSWORD = "1234567890"

NORMAL_SERVER_IP = "192.168.8.132"
NORMAL_SERVER_PORT = 9090

HONEYPOT_IP = "192.168.8.132"
HONEYPOT_PORT = 8080

DLI_LISTEN_HOST = "0.0.0.0"
DLI_LISTEN_PORT = 5000

SNORT_ALERT_TIMEOUT = 10
DLI_RESULT_TIMEOUT = 30

# fixed = 測試用
# socket = 接機架 DLI 回傳
DLI_MODE = "socket"

# fixed 模式用
DLI_FIXED_RESULT = 0