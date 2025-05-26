import socket

def test_network_ports(domain):
    ports = [21, 22, 23, 25, 80, 443, 3306, 8080]
    open_ports = []

    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((domain.replace("http://", "").replace("https://", "").split("/")[0], port))
            open_ports.append(f"Port {port} açık")
            s.close()
        except:
            pass

    return open_ports
