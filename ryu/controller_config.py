snortport = 51234

controller_port = 6653
controller_ip = "127.0.0.1"

# Database settings (Connect to local DB for high-speed packet logging and quick query)
DB_HOST = "localhost"
DB_PORT = 5432
DB_NAME = "security_db"
DB_USER = "data_user"
DB_PASSWORD = "1234567890"

# Remote Rack Connection settings (For SSH CLI pipeline reference)
REMOTE_DB_HOST = "140.130.34.85"
REMOTE_DB_PORT = 52739

NORMAL_SERVER_IP = "192.168.8.132"
NORMAL_SERVER_PORT = 9090

HONEYPOT_IP = "192.168.8.132"
HONEYPOT_PORT = 8080

# DLI socket listener
DLI_LISTEN_HOST = "0.0.0.0"
DLI_LISTEN_PORT = 5000

# Snort alert 有效時間，秒
SNORT_ALERT_TIMEOUT = 10

# DLI 結果有效時間，秒
DLI_RESULT_TIMEOUT = 30