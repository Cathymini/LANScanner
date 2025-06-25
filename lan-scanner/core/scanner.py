import socket
import threading
from queue import Queue
from core.fingerprint import load_fingerprints, fingerprint_identify 
import requests

class PortScannerThread(threading.Thread):
    def __init__(self, ip, port_queue, result_queue, fingerprints):
        super().__init__()
        self.ip = ip
        self.port_queue = port_queue
        self.result_queue = result_queue
        self.fingerprints = fingerprints

    def run(self):
        while not self.port_queue.empty():
            port = self.port_queue.get()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect((self.ip, port))
                    
                    # 尝试识别服务
                    service = self.identify_service(port)
                    cms = fingerprint_identify(self.ip, port, self.fingerprints)
                    
                    self.result_queue.put((port, "open", service, cms))
            except:
                self.result_queue.put((port, "closed", "unknown", "unknown"))

    def identify_service(self, port):
        # 常见端口服务映射
        common_ports = {
  
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            8080: "HTTP Proxy"
        }
        return common_ports.get(port, "unknown")

def multi_threaded_scan(ip, port_range, num_threads):
    port_queue = Queue()
    result_queue = Queue()
    fingerprints = load_fingerprints()

    for port in range(port_range[0], port_range[1] + 1):
        port_queue.put(port)

    threads = []
    for _ in range(num_threads):
        thread = PortScannerThread(ip, port_queue, result_queue, fingerprints)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    scan_results = []
    while not result_queue.empty():
        scan_results.append(result_queue.get())

    return scan_results