import nmap
import json
import os
import socket
import fcntl
import struct
import netifaces
import subprocess
from rich.console import Console
from rich.table import Table

console = Console()
saved_file = "network_devices.json"

def check_nmap_installed():
    """بررسی نصب بودن nmap و دسترسی‌های لازم"""
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            console.print("[red]nmap نصب نیست یا دسترسی کافی ندارید. لطفاً nmap را نصب کنید.[/red]")
            exit(1)
    except FileNotFoundError:
        console.print("[red]nmap یافت نشد. لطفاً nmap را نصب کنید.[/red]")
        exit(1)

def detect_active_interface():
    """پیدا کردن اولین اینترفیس فعال به‌جز lo"""
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        if iface == 'lo':
            continue
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            return iface
    console.print("[yellow]هیچ اینترفیس فعالی یافت نشد. استفاده از eth0 به‌صورت پیش‌فرض.[/yellow]")
    return "eth0"

def get_current_subnet(interface):
    """دریافت IP و subnet mask از سیستم"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', interface[:15].encode()))[20:24])
        netmask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, struct.pack('256s', interface[:15].encode()))[20:24])
        ip_parts = list(map(int, ip.split('.')))
        mask_parts = list(map(int, netmask.split('.')))
        network = [ip_parts[i] & mask_parts[i] for i in range(4)]
        cidr = sum(bin(x).count('1') for x in mask_parts)
        return f"{'.'.join(map(str, network))}/{cidr}"
    except Exception as e:
        console.print(f"[red]خطا در دریافت subnet: {e}. استفاده از پیش‌فرض 192.168.1.0/24[/red]")
        return "192.168.1.0/24"

def scan_network(subnet):
    """اسکن شبکه با nmap"""
    scan_type = "-T4 -F"  # تنظیم پیش‌فرض برای اسکن
    console.print(f"[cyan]در حال اسکن شبکه: {subnet} با آرگومان‌های {scan_type}[/cyan]")
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=subnet, arguments=scan_type)
    except nmap.PortScannerError as e:
        console.print(f"[red]خطا در اسکن شبکه: {e}[/red]")
        return []

    devices = []
    for host in scanner.all_hosts():
        device = {
            "ip": host,
            "hostname": scanner[host].hostname() or "-",
            "state": scanner[host].state(),
            "open_ports": list(scanner[host]["tcp"].keys()) if "tcp" in scanner[host] else []
        }
        devices.append(device)
    return devices

def save_devices(devices):
    """ذخیره داده‌ها در فایل JSON"""
    try:
        with open(saved_file, "w") as f:
            json.dump(devices, f, indent=2)
    except Exception as e:
        console.print(f"[red]خطا در ذخیره داده‌ها: {e}[/red]")

def compare_with_previous(current_devices):
    """مقایسه با داده‌های قبلی"""
    if not os.path.exists(saved_file):
        return []

    try:
        with open(saved_file, "r") as f:
            previous = json.load(f)
    except Exception as e:
        console.print(f"[red]خطا در خواندن داده‌های قبلی: {e}[/red]")
        return []

    old_ips = {dev["ip"] for dev in previous}
    current_ips = {dev["ip"] for dev in current_devices}
    new_ips = current_ips - old_ips
    return [dev for dev in current_devices if dev["ip"] in new_ips]

def show_table(devices, new_only=False):
    """چاپ نتایج در قالب جدول"""
    table = Table(title="نتایج اسکن شبکه")
    table.add_column("IP")
    table.add_column("Hostname")
    table.add_column("وضعیت")
    table.add_column("پورت‌های باز")

    for dev in devices:
        table.add_row(
            dev["ip"],
            dev["hostname"],
            dev["state"],
            ", ".join(map(str, dev["open_ports"])) if dev["open_ports"] else "ندارد"
        )

    if new_only:
        console.print("[yellow]تجهیزات جدید پیدا شدند:[/yellow]")
    console.print(table)

def check_vpn(host):
    """بررسی VPN"""
    return 443 in host.get("open_ports", [])

def check_intranet(ip):
    """بررسی Intranet"""
    private_ranges = [
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255")
    ]
    for start, end in private_ranges:
        if ip >= start and ip <= end:
            return True
    return False

def check_honeypot(devices):
    """بررسی Honeypot با معیارهای دقیق‌تر"""
    suspicious_ips = []
    for dev in devices:
        # Honeypot اگر تعداد پورت‌های باز زیاد باشد یا پاسخ‌های غیرعادی داشته باشد
        if len(dev["open_ports"]) > 10 or (80 in dev["open_ports"] and 22 in dev["open_ports"] and 445 in dev["open_ports"]):
            suspicious_ips.append(dev["ip"])
    return suspicious_ips

def check_firewall():
    """بررسی فایروال"""
    try:
        result = subprocess.run(["iptables", "-L"], capture_output=True, text=True, check=True)
        return "Chain" in result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        console.print(f"[red]خطا در بررسی فایروال: {e}[/red]")
        return False

def check_ids_ips():
    """بررسی IDS/IPS"""
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True, check=True)
        output = result.stdout
        if "snort" in output or "suricata" in output:
            return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        console.print(f"[red]خطا در بررسی IDS/IPS: {e}[/red]")
    return False

if __name__ == "__main__":
    # بررسی نصب nmap
    check_nmap_installed()

    # شناسایی اینترفیس
    interface = detect_active_interface()
    console.print(f"[green]اینترفیس فعال شناسایی شد:[/green] {interface}")

    # دریافت subnet
    subnet = get_current_subnet(interface)
    
    # اسکن شبکه
    devices = scan_network(subnet)
    
    # مقایسه با داده‌های قبلی
    new_devices = compare_with_previous(devices)
    
    # نمایش نتایج
    show_table(new_devices if new_devices else devices, new_only=bool(new_devices))
    
    # ذخیره داده‌ها
    save_devices(devices)

    # بررسی VPN، Intranet، Honeypot
    vpn_devices = [dev for dev in devices if check_vpn(dev)]
    intranet_devices = [dev for dev in devices if check_intranet(dev["ip"])]
    honeypot_devices = check_honeypot(devices)

    console.print(f"[cyan]دستگاه‌های مشکوک به VPN:[/cyan] {vpn_devices}")
    console.print(f"[cyan]دستگاه‌های شبکه داخلی:[/cyan] {intranet_devices}")
    console.print(f"[cyan]دستگاه‌های مشکوک به Honeypot:[/cyan] {honeypot_devices}")

    # بررسی فایروال و IDS/IPS
    firewall_status = check_firewall()
    ids_ips_status = check_ids_ips()

    console.print(f"[cyan]وضعیت فایروال: {'فعال' if firewall_status else 'غیرفعال'}")
    console.print(f"[cyan]وضعیت IDS/IPS: {'فعال' if ids_ips_status else 'غیرفعال'}")

    console.print(f"\n[green]اسکن کامل شد. گزارش ذخیره شد در:[/green] {saved_file}")
