# Petro - ابزار اسکن و تحلیل شبکه


یک اسکریپت پایتون است که برای اسکن و تحلیل شبکه محلی شما طراحی شده است. این ابزار به شما کمک می‌کند تا دستگاه‌های متصل به شبکه خود را کشف کرده و اطلاعات امنیتی حیاتی را در مورد آنها به دست آورید.

## قابلیت‌ها

  * **کشف دستگاه‌ها:** دستگاه‌های فعال در شبکه شما را شناسایی می‌کند.
  * **شناسایی پورت‌های باز:** پورت‌های TCP باز روی دستگاه‌های کشف شده را نمایش می‌دهد.
  * **مقایسه اسکن‌ها:** دستگاه‌های جدیدی که به شبکه شما پیوسته‌اند را از آخرین اسکن تشخیص می‌دهد.
  * **تحلیل امنیتی اولیه:**
      * دستگاه‌های مشکوک به اجرای VPN را بررسی می‌کند.
      * دستگاه‌هایی را که به شبکه داخلی (اینترانت) شما تعلق دارند شناسایی می‌کند.
      * دستگاه‌های مشکوک به Honeypot (تله امنیتی) را با استفاده از معیارهای پیشرفته شناسایی می‌کند.
      * وضعیت فایروال سیستم را بررسی می‌کند.
      * وجود سیستم‌های تشخیص/جلوگیری از نفوذ (IDS/IPS) مانند Snort یا Suricata را بررسی می‌کند.
  * **گزارش‌دهی:** نتایج اسکن را در یک فایل JSON ذخیره می‌کند (`network_devices.json`) و آنها را در یک جدول خوانا در کنسول نمایش می‌دهد.

### پیش‌نیازها

  * **Nmap:** ابزار اسکن شبکه Nmap باید روی سیستم شما نصب باشد.

### نصب

1.  پروژه را دانلود کنید
2.  پیش‌نیازهای پایتون را نصب کنید:
    (  `pip install python-nmap rich netifaces` )

### اجرا

اسکریپت را با مجوزهای کافی اجرا کنید:

```bash
sudo python3 petro.py
```

## استفاده

پس از اجرا، اسکریپت به طور خودکار رابط فعال شبکه شما را شناسایی کرده، زیرشبکه را تعیین می‌کند و اسکن را آغاز می‌کند. نتایج به صورت یک جدول در کنسول نمایش داده می‌شوند و در فایل `network_devices.json` ذخیره می‌گردند. هر دستگاه جدیدی که از اسکن قبلی پیدا شود، مشخص خواهد شد.

## مجوز

این پروژه تحت مجوز MIT منتشر شده است. برای جزئیات بیشتر به فایل [LICENSE](LICENSE) مراجعه کنید.

---

---

# Petro - Network Scanning and Analysis Tool


It is a Python script designed to scan and analyze your local network. This tool helps you discover the devices connected to your network and obtain critical security information about them.

## Features

  * **Device Discovery:** Identifies active devices on your network.
  * **Open Port Detection:** Displays open TCP ports on discovered devices.
  * **Scan Comparison:** Detects new devices that have joined your network since the last scan.
  * **Basic Security Analysis:**
      * Checks for devices suspected of running a VPN.
      * Identifies devices belonging to your internal network (intranet).
      * Identifies devices suspected of being a Honeypot (security trap) using advanced criteria.
      * Checks the status of the system firewall.
      * Checks for the presence of Intrusion Detection/Prevention Systems (IDS/IPS) such as Snort or Suricata.
  * **Reporting:** Saves scan results to a JSON file (`network_devices.json`) and displays them in a readable table in the console.

### Prerequisites

  * **Nmap:** The Nmap network scanning tool must be installed on your system.

### Installation

1.  Download the project
2.  Install the Python prerequisites:
    (  `pip install python-nmap rich netifaces` )

### Running

Run the script with sufficient permissions:

```bash
sudo python3 petro.py
```

## Usage

After running, the script automatically identifies your active network interface, determines the subnet, and begins the scan. The results are displayed as a table in the console and saved to the `network_devices.json` file. Any new device found since the previous scan will be flagged.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


![Repo Badge](https://visitor-badge.laobi.icu/badge?page_id=null-err0r.Petro) 
