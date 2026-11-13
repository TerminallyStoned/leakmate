# DNSExfiltrator on Linux: the day-1 answer

Card #8 says "check on day 1 whether the PowerShell client runs under `pwsh` on Linux".
It does not. Tested, not guessed:

1. `mcr.microsoft.com/powershell:7.4-ubuntu-22.04` (pwsh 7.4.6, Ubuntu 22.04.5).
2. The client script `Invoke-DNSExfiltrator.ps1` contains no Windows-only cmdlets. It
   base64-decodes an embedded assembly and calls it:
   `[System.Reflection.Assembly]::Load($bytes)` → `[DNSExfiltrator.DNSExfiltrator]::Main($Args)`.
3. `Assembly::Load` **succeeds** on the shipped `release/dnsExfiltrator.dll` (21 504 bytes,
   PE32 Mono/.Net i386). So the usual "PowerShell Core cannot load .NET Framework
   assemblies" story is *not* the blocker.
4. The blocker is one line later. In `dnsExfiltrator.cs`, `DnsResolver.GetTXTRecord`
   opens with `if (Environment.OSVersion.Platform != PlatformID.Win32NT) { throw new
   NotSupportedException(); }` (lines 581-585 of the file on `master`) and then P/Invokes
   `dnsapi!DnsQuery_W` / `DnsRecordListFree`. The first TXT query — the `init.` probe —
   throws `System.NotSupportedException`. The assembly's own strings confirm the Windows
   target: `mscorie.dll`, `.NET Framework 4.0.30319`, `System.Runtime.InteropServices`.

Options we do **not** want, and why:

* `h=google` / `h=cloudflare` switches the class to `DOHResolver`, which is plain HTTPS and
  would probably run under pwsh/Linux — but it sends the exfil to Google's resolver, which
  breaks the containment premise of the testbed.
* `dnsExfiltrator.js` is not a Node client: it is a `new ActiveXObject('WScript.Shell')` +
  .NET-interop blob, Windows-only too.
* A Windows container or VM on the internal network works in principle, but adds an
  untested OS to a 10-day project for one tool, and the DNS traffic would be identical to
  what we can generate in 180 lines.
* The receiver `dnsexfiltrator.py` is Python 2 only (`xrange`, `print x`) and binds UDP 53 —
  it needed porting either way.

Decision: port both ends to Python 3 (`testbed/tools/dnsexfiltrator/`) and keep the **on-wire
format byte-identical** to the real tool, so the captures are still representative:

```
file -> in-memory ZIP -> RC4(password) -> Base64URL ('=' stripped, '/'->'_', '+'->'-')
init query   init.<base32("<file>|<nbChunks>")>.base64.<domain>   expects TXT "OK"
data query   <chunkIndex>.<label>.<label>…<domain>                expects TXT <chunkIndex>
```

`labelMaxSize` 63, `bytesLeft = requestMaxSize - 10`, `nbChunks = len(data)//chunkMaxSize + 1`,
`--base32` for the Base32 alphabet, `--rate` for the per-chunk sleep. Because the names match
upstream, they also match the signature `scripts/cic_to_queries.py` uses for CIC-Bell labels
(`^(init\.[A-Za-z2-7]{8,}|\d+\.[A-Za-z0-9_-]{8,})`).

Verified on 13 Nov 2026 in the lab: 4 096 random bytes exfiltrated from
`dnsexfiltrator-cli` to `dnsexfiltrator-ns` (31 queries), the server wrote `secret.bin.zip`,
and the zip member extracted byte-identical — md5 `6d7861824659d359a9d0b968c6530ac3` on both
sides. At `--rate 5` a 12 KB payload measured 5.06 queries/second in the capture.

If the marker "must be the real binary" matters for the report, the honest statement is: the
real client cannot run in our lab (Windows-only DNS API), the port reproduces its wire
format, and that is a limitation to name in the dataset section, not to hide.
