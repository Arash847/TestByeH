# Dump kernel text from prosper0gdb on Windows, no GDB and no WSL.
#
# prosper0gdb implements the standard GDB Remote Serial Protocol (it
# handles "qSupported:"), so a minimal client is enough to read memory.
# This avoids requiring gdb-multiarch, which wants a Unix environment.
#
# Usage (after kstuff.elf is loaded and prosper0gdb is listening):
#   powershell -ExecutionPolicy Bypass -File r0gdb-dump.ps1 `
#       -Console <ps5-ip> -Port 1234 `
#       -Start 0xFFFFFFFF81000000 -End 0xFFFFFFFF81C70000 `
#       -Out ktext-8.60.bin
#
# Note: -Console, not -Host. $Host is a reserved PowerShell automatic
# variable and cannot be used as a parameter name.
#
# Pass -Out as an absolute path if you care where it lands. PowerShell's
# location and the .NET current directory can differ, and a relative path
# resolves against the latter.
#
# READ-ONLY. This client only ever issues memory-read packets. It never
# writes, steps, or continues. Do not add such commands: r0gdb is a
# ring-0 stub and a stray write bricks the console.

param(
  [Parameter(Mandatory=$true)][string]$Console,
  [int]$Port = 1234,
  [string]$Start = "0xFFFFFFFF81000000",
  [string]$End   = "0xFFFFFFFF81C70000",
  [string]$Out   = "ktext-8.60.bin",
  [int]$Chunk    = 0x1000
)

$ErrorActionPreference = "Stop"

$startAddr = [Convert]::ToUInt64($Start.Substring(2), 16)
$endAddr   = [Convert]::ToUInt64($End.Substring(2), 16)

# Resolve to an absolute path up front. [IO.File]::Create() resolves
# relative paths against the .NET current directory while Move-Item
# resolves against the PowerShell location; those can differ, which
# silently produced a file the script could then not find.
$Out = [IO.Path]::GetFullPath($Out)

$total     = $endAddr - $startAddr
if ($total -le 0) { throw "End must be greater than Start" }
if ($Chunk -le 0 -or ($Chunk % 2) -ne 0) { throw "Chunk must be a positive even number" }

Write-Host "[r0gdb] connecting to $Console`:$Port ..."
$client = New-Object Net.Sockets.TcpClient
$client.Connect($Console, $Port)
$stream = $client.GetStream()
$stream.ReadTimeout = 30000
$stream.WriteTimeout = 30000

function Get-Checksum([string]$s) {
  $sum = 0
  foreach ($c in $s.ToCharArray()) { $sum += [int][char]$c }
  return ($sum -band 0xFF)
}

function Send-Packet([string]$payload) {
  $pkt = '$' + $payload + '#' + ('{0:x2}' -f (Get-Checksum $payload))
  $b = [Text.Encoding]::ASCII.GetBytes($pkt)
  $stream.Write($b, 0, $b.Length)
  $stream.Flush()
}

# Read one packet. Handles leading '+' / '-' acks and the '$' framing.
function Read-Packet {
  $sb = New-Object Text.StringBuilder
  $state = "seek"   # seek -> body -> csum
  $csumRead = 0
  while ($true) {
    $b = New-Object byte[] 1
    $n = $stream.Read($b, 0, 1)
    if ($n -le 0) { throw "connection closed while reading a packet" }
    $ch = [char]$b[0]

    switch ($state) {
      "seek" {
        if ($ch -eq '$') { $state = "body" }
        # '+' and '-' are acks; anything else before '$' is ignored
      }
      "body" {
        if ($ch -eq '#') { $state = "csum" }
        else { [void]$sb.Append($ch) }
      }
      "csum" {
        $csumRead++
        if ($csumRead -ge 2) {
          $payload = $sb.ToString()
          # Acknowledge so the stub keeps sending
          $ack = [Text.Encoding]::ASCII.GetBytes("+")
          $stream.Write($ack, 0, 1)
          $stream.Flush()
          return $payload
        }
      }
    }
  }
}

function Invoke-Remote([string]$payload) {
  Send-Packet $payload
  return Read-Packet
}

# --- handshake -------------------------------------------------------
$sup = Invoke-Remote "qSupported:multiprocess+"
Write-Host "[r0gdb] qSupported -> $sup"

# Switch to no-ack mode: removes per-packet acks and simplifies streaming.
# QStartNoAckMode is acknowledged with a BARE '+' byte, not with a reply
# packet, so it must not go through Read-Packet -- that would block forever
# waiting for a '$' that never arrives.
Send-Packet "QStartNoAckMode"
$ackBuf = New-Object byte[] 1
$null = $stream.Read($ackBuf, 0, 1)
if ([char]$ackBuf[0] -ne '+') {
  throw ("expected '+' ack for QStartNoAckMode, got '{0}'" -f [char]$ackBuf[0])
}
Write-Host "[r0gdb] no-ack mode enabled"

# --- sanity check ----------------------------------------------------
$probe = "m{0:x},{1:x}" -f $startAddr, 16
$resp = Invoke-Remote $probe
if ($resp -like "E*" -or $resp -eq "") {
  throw "stub refused a read at $Start : '$resp' (wrong port, or stub not loaded)"
}
Write-Host "[r0gdb] first 16 bytes: $resp"

# --- dump ------------------------------------------------------------
$partial = "$Out.partial"
if (Test-Path $partial) { Remove-Item $partial }
$fs = [IO.File]::Create($partial)

$done = [uint64]0
$chunks = [math]::Ceiling($total / $Chunk)
$n = 0
$sw = [Diagnostics.Stopwatch]::StartNew()

while ($done -lt $total) {
  $want = [math]::Min($Chunk, $total - $done)
  $addr = $startAddr + $done
  $r = Invoke-Remote ("m{0:x},{1:x}" -f $addr, $want)

  if ($r -like "E*") {
    throw "read failed at 0x{0:x} (offset 0x{1:x}) : {2}" -f $addr, $done, $r
  }
  if ($r.Length -ne $want * 2) {
    throw "short read at 0x{0:x}: got {1} hex chars, expected {2}" -f $addr, $r.Length, ($want * 2)
  }

  $bytes = [byte[]]::new($want)
  for ($i = 0; $i -lt $want; $i++) {
    $bytes[$i] = [Convert]::ToByte($r.Substring($i * 2, 2), 16)
  }
  $fs.Write($bytes, 0, $want)
  $done += $want
  $n++

  if (($n % 64) -eq 0) {
    $pct = [math]::Round(100.0 * $done / $total, 1)
    Write-Host ("[r0gdb] {0,6:N1}%  {1} / {2} bytes" -f $pct, $done, $total)
  }
}

$sw.Stop()
$fs.Flush(); $fs.Close()
$client.Close()

Move-Item -Force $partial $Out
$hash = (Get-FileHash -Algorithm SHA256 $Out).Hash.ToLower()

Write-Host ""
Write-Host ("[r0gdb] wrote {0} ({1:N2} MB) in {2:N1}s" -f $Out, ((Get-Item $Out).Length / 1MB), $sw.Elapsed.TotalSeconds)
Write-Host "[r0gdb] sha256 $hash"
Write-Host "[r0gdb] expected size 0x{0:x} ({1} bytes)" -f $total, $total


