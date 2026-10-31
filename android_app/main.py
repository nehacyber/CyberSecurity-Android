import threading
import time
import socket
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from kivy.app import App
from kivy.clock import Clock
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class CyberSecurityApp(App):
    def build(self):
        self.title = "CyberSecurity Toolkit"
        self.root_box = BoxLayout(
            orientation="vertical",
            padding=dp(14),
            spacing=dp(10),
        )

        self.root_box.add_widget(Label(
            text="[b]CYBERSECURITY TOOLKIT[/b]",
            markup=True,
            font_size="23sp",
            size_hint_y=None,
            height=dp(55),
        ))

        self.root_box.add_widget(Label(
            text="Website Checker & Security Analyzer",
            font_size="14sp",
            size_hint_y=None,
            height=dp(30),
        ))

        self.url_input = TextInput(
            hint_text="https://example.com",
            multiline=False,
            size_hint_y=None,
            height=dp(48),
        )
        self.root_box.add_widget(self.url_input)

        buttons = BoxLayout(
            size_hint_y=None,
            height=dp(50),
            spacing=dp(8),
        )

        check_button = Button(text="Check Website")
        check_button.bind(on_press=self.check_website)
        buttons.add_widget(check_button)

        headers_button = Button(text="Security Headers")
        headers_button.bind(on_press=self.check_headers)
        buttons.add_widget(headers_button)

        self.root_box.add_widget(buttons)

        self.result = Label(
            text="Enter a website address to begin.",
            markup=True,
            halign="left",
            valign="top",
            size_hint_y=None,
        )
        self.result.bind(
            width=lambda instance, width:
            setattr(instance, "text_size", (width, None))
        )
        self.result.bind(
            texture_size=lambda instance, size:
            setattr(instance, "height", size[1] + dp(25))
        )

        scroll = ScrollView()
        scroll.add_widget(self.result)
        self.root_box.add_widget(scroll)

        self.root_box.add_widget(Label(
            text="Use only on websites you are authorized to test.",
            font_size="11sp",
            size_hint_y=None,
            height=dp(28),
        ))

        return self.root_box

    def get_url(self):
        url = self.url_input.text.strip()

        if not url:
            raise ValueError("Please enter a website address.")

        if "://" not in url:
            url = "https://" + url

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Enter a valid HTTP or HTTPS website.")

        if parsed.username or parsed.password:
            raise ValueError("URLs containing usernames or passwords are not allowed.")

        return url

    def check_website(self, _button):
        try:
            url = self.get_url()
        except ValueError as exc:
            self.result.text = str(exc)
            return

        self.result.text = "Checking website..."
        threading.Thread(
            target=self._check_website_worker,
            args=(url,),
            daemon=True,
        ).start()

    def _check_website_worker(self, url):
        start = time.perf_counter()

        try:
            request = Request(
                url,
                headers={"User-Agent": "CyberSecurityToolkit/1.0"},
            )

            try:
                with urlopen(request, timeout=10) as response:
                    status = response.status
                    final_url = response.geturl()
                    headers = response.headers
            except HTTPError as exc:
                status = exc.code
                final_url = exc.geturl()
                headers = exc.headers

            elapsed = (time.perf_counter() - start) * 1000
            host = urlparse(final_url).hostname
            ip = socket.gethostbyname(host) if host else "Unavailable"

            text = (
                "[b]WEBSITE CHECK REPORT[/b]\n\n"
                f"Website: {host}\n"
                f"Protocol: {urlparse(final_url).scheme.upper()}\n"
                f"HTTP Status: {status}\n"
                f"Response Time: {elapsed:.2f} ms\n"
                f"Resolved IP: {ip}\n"
                f"Content Type: {headers.get('Content-Type', 'Unknown')}\n\n"
                "Note: A successful response does not guarantee that a website is secure."
            )

        except (URLError, TimeoutError, OSError, ValueError) as exc:
            text = f"Website check failed:\n{str(exc)}"
        except Exception as exc:
            text = f"Unexpected error:\n{str(exc)}"

        Clock.schedule_once(
            lambda _dt: setattr(self.result, "text", text)
        )

    def check_headers(self, _button):
        try:
            url = self.get_url()
        except ValueError as exc:
            self.result.text = str(exc)
            return

        self.result.text = "Analyzing security headers..."
        threading.Thread(
            target=self._headers_worker,
            args=(url,),
            daemon=True,
        ).start()

    def _headers_worker(self, url):
        try:
            request = Request(
                url,
                headers={"User-Agent": "CyberSecurityToolkit/1.0"},
            )

            try:
                with urlopen(request, timeout=10) as response:
                    status = response.status
                    headers = response.headers
            except HTTPError as exc:
                status = exc.code
                headers = exc.headers

            lines = [
                "[b]SECURITY HEADER REPORT[/b]",
                "",
                f"HTTP Status: {status}",
                "",
            ]

            found = 0

            for header in SECURITY_HEADERS:
                value = headers.get(header)

                if value:
                    found += 1
                    lines.append(f"[color=00AA00]FOUND[/color] {header}: {value}")
                else:
                    lines.append(f"[color=FF9900]NOT FOUND[/color] {header}")

            lines.extend([
                "",
                f"Headers found: {found}/{len(SECURITY_HEADERS)}",
                "",
                "Missing headers alone do not prove a vulnerability.",
            ])

            text = "\n".join(lines)

        except Exception as exc:
            text = f"Header analysis failed:\n{str(exc)}"

        Clock.schedule_once(
            lambda _dt: setattr(self.result, "text", text)
        )


if __name__ == "__main__":
    CyberSecurityApp().run()
