[app]

title = CyberSecurity Toolkit
package.name = cybersecuritytoolkit
package.domain = org.nehacyber
source.dir = .
source.include_exts = py,txt,png,jpg,kv
version = 1.0.0

requirements = python3,kivy

orientation = portrait
fullscreen = 0

android.permissions = INTERNET
android.api = 35
android.minapi = 26
android.archs = arm64-v8a
android.accept_sdk_license = True

[buildozer]

log_level = 2
warn_on_root = 1
