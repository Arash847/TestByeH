# Race the prosper0gdb stub for its single accept() opportunity.
#
# real_dbg_enter() calls accept() exactly ONCE per kstuff load, then
# returns. A stub that has already consumed a connection will still have
# its port open but will never answer again -- which is what "connects
# fine, then silence" looks like.
#
# ps5-kstuff/main.c pushes "allocating kernel memory..." over the socket
# right after dbg_enter(), so a client connected DURING that window sees
# traffic. Connect too early and the stub is not listening yet; too late
# and init is finished with nothing left to push.
#
# So: poll aggressively, take the first connect that succeeds, then log
# everything the stub sends and probe whether it will service a read.
#
# Start this FIRST, then load kstuff.elf on the console.
#
#   powershell -ExecutionPolicy Bypass -File probe-session.ps1 -Console <ip>

param(
  [Parameter(Mandatory=$true)][string]$Console,
  [int]$Port = 1234,
  [int]$WaitSeconds = 300,
  [int]$ListenSeconds = 90
)

$ErrorActionPreference = "Continue"
$deadline = (Get-Date).AddSeconds($WaitSeconds)

function Get-Checksum([string]$s) {
  $sum = 0
  foreach ($c in $s.ToCharArray()) { $sum += [int][char]$c }
  return ($sum -band 0xFF)
}

Write-Host "[probe] polling $Console`:$Port for up to $WaitSeconds s ..."
Write-Host "[probe] >>> load kstuff.elf on the console NOW <<<"

$client = $null
while ((Get-Date) -lt $deadline) {
  try {
    $c = New-Object Net.Sockets.TcpClient
    $iar = $c.BeginConnect($Console, $Port, $null, $null)
    if ($iar.AsyncWaitHandle.WaitOne(200)) {
      $c.EndConnect($iar)
      $client = $c
      Write-Host "[probe] CONNECTED at $(Get-Date -Format 'HH:mm:ss')"
      break
    }
    $c.Close()
  } catch { }
}

if (-not $client) { Write-Host "[probe] never connected"; exit 1 }

$stream = $client.GetStream()
$stream.ReadTimeout = 3000
$stream.WriteTimeout = 10000

# The stub requires a literal '+' as the first byte or it bails out.
$hello = [Text.Encoding]::ASCII.GetBytes("+")
$stream.Write($hello, 0, 1)
$stream.Flush()
Write-Host "[probe] sent '+'"

function Send-Packet([string]$payload) {
  $pkt = '$' + $payload + '#' + ('{0:x2}' -f (Get-Checksum $payload))
  $b = [Text.Encoding]::ASCII.GetBytes($pkt)
  $stream.Write($b, 0, $b.Length)
  $stream.Flush()
}

# Phase 1: passively log whatever the stub pushes on its own.
Write-Host "[probe] listening passively for $ListenSeconds s ..."
$sw = [Diagnostics.Stopwatch]::StartNew()
$log = New-Object Text.StringBuilder
$buf = New-Object byte[] 8192
$got = 0

while ($sw.Elapsed.TotalSeconds -lt $ListenSeconds) {
  try { $n = $stream.Read($buf, 0, $buf.Length) } catch { continue }
  if ($n -le 0) { Write-Host "[probe] socket closed by peer"; break }
  $got += $n
  $chunk = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
  [void]$log.Append($chunk)
  Write-Host "[probe] <<< $chunk"
}

Write-Host "[probe] passive phase received $got bytes"

# Phase 2: see whether the stub services a read request outside a trap.
if ($got -gt 0) {
  Write-Host "[probe] sending a memory-read request ..."
  Send-Packet "m{0:x},10" -f 0xFFFFFFFF81000000
  $sw2 = [Diagnostics.Stopwatch]::StartNew()
  while ($sw2.Elapsed.TotalSeconds -lt 20) {
    try { $n = $stream.Read($buf, 0, $buf.Length) } catch { continue }
    if ($n -le 0) { break }
    Write-Host "[probe] <<< $([Text.Encoding]::ASCII.GetString($buf,0,$n))"
  }
} else {
  Write-Host "[probe] nothing arrived; the stub only services packets from a trap."
  Write-Host "[probe] A packet sent now would sit unread in the socket buffer."
}

$client.Close()
Write-Host "[probe] done"
