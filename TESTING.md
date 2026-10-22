# Community test report

## macOS guided terminal wizard

Offline tests cover enrollment validation and atomic saving, elapsed-time connection/confirmation deadlines, watchdog timing, cancellation and repeated attempts, relay failures, recovery failures and honest result classification. `portal_tui.py --demo` exercises the screens without network or configuration changes. These checks do not replace a real-device test of the wizard.

- macOS / Python / Portal firmware versions:
- Start.command opened the wizard; terminal dimensions:
- Saved enrollment was pre-filled correctly; new enrollment saved and reloaded:
- Prerequisite keywords, editable fields and bitrate selection were clear:
- WAIT changed visibly to READY; CONNECT NOW showed a full 120-second countdown:
- Success and incomplete attempts had distinct labels and brief effects:
- Motion-free mode, monochrome terminals and 72x24 layout remained usable:
- Fresh connection: modified request, acceptance, three high target reports and local egress verified:
- Picture and controls remained usable after direct-path restoration:
- Connecting near the end of the countdown left time for confirmation:
- No-connection timeout and Q/Esc/Ctrl-C cancellation restored the direct path:
- A second guided attempt worked after cancellation or success:
- Profile, PS5-reported target, actual Portal observations and restoration errors:

Keep real configuration, reports, recovery state and captures private. Do not call a reported target a measured sustained video bitrate.


## v0.3.0 automation / Linux preview

- OS version and architecture:
- Deployment (native / Proxmox LXC / Docker macvlan) and host:
- Ethernet/Wi-Fi adapter (and Npcap version on Windows):
- Profile (65/100/200):
- Baseline picture/control usable, recovery complete:
- Foreground active trial and Portal display range:
- Windows SYSTEM task / Linux systemd / container OpenRC or Docker startup result:
- Fresh Portal disconnect/reconnect result:
- Host reboot result:
- Graceful stop recovery result:
- Crash recovery result (only if intentionally tested):
- Stutter, input-response observations (not a benchmark):
- Sanitized error message:

Do not attach real enrollment/config files, raw captures, runtime folders, credentials or private addresses. A modified startup counter is not confirmation of PS5 acceptance. Failed or untested steps should be reported as such.
