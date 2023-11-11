import re

def read_firewall_log(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    return lines

def process_firewall_log(log_lines):
    threats = []

    # Skip the header line
    for line in log_lines[1:]:
        # Split the line into fields
        fields = re.split(r'\s+', line.strip())

        # Extract relevant information
        date = fields[0]
        time = fields[1]
        action = fields[2]
        protocol = fields[3]
        src_ip = fields[4]
        dst_ip = fields[5]
        src_port = fields[6]
        dst_port = fields[7]
        size = fields[8]
        tcp_flags = fields[9]
        info = ' '.join(fields[10:])

        # Check for potential threats
        if action == 'BLOCK' and (protocol == 'TCP' or protocol == 'UDP' or protocol == 'ICMP'):
            threat_info = f"***Potential threat detected***\nDate: {date} \nTime: {time}\nAction: {action} \nProtocol: {protocol}\nSource IP: {src_ip} \nDestination IP: {dst_ip}\nSource Port: {src_port} \nDestination Port: {dst_port}\nSize: {size} \nTCP Flags: {tcp_flags}\nInfo: {info}\n"
            threats.append(threat_info)

    return threats

def generate_report(threats):
    if threats:
        report = "\nThreat report of the ABC firewall\n\n"
        for threat in threats:
            report += threat + '\n'
    else:
        report = "No potential threats found in the log file."
    
    return report

def main():
    file_path = 'firewalllog.txt'  # firewall log file name
    log_lines = read_firewall_log(file_path)
    threats = process_firewall_log(log_lines)
    report = generate_report(threats)

    print(report)

if __name__ == "__main__":
    main()
