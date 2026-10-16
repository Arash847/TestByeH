# Mock GDB Remote Serial Protocol server, used to test r0gdb-dump.ps1
# without touching a console. Serves a deterministic pattern so the dump
# can be verified byte for byte.
#
#   Start-Job -ScriptBlock { .\mock-r0gdb.ps1 -Port 5555 }
#   .\r0gdb-dump.ps1 -Host 127.0.0.1 -Port 5555 -Start 0x1000 -End 0x5000 -Out test.bin
param([int]$Port = 5555)

$ErrorActionPreference = "Stop"

function Get-Checksum([string]$s) {
  $sum = 0
  foreach ($c in $s.ToCharArray()) { $sum += [int][char]$c }
  return ($sum -band 0xFF)
}

# Deterministic "memory": byte at addr A is (A * 7 + 13) & 0xFF
function Get-Byte([uint64]$a) { return [byte](($a * 7 + 13) -band 0xFF) }

$listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $Port)
$listener.Start()
Write-Host "[mock] listening on 127.0.0.1:$Port"

$client = $listener.AcceptTcpClient()
$stream = $client.GetStream()
$stream.ReadTimeout = 60000
Write-Host "[mock] client connected"

# Mirror the real stub, which abandons itself unless the first byte on the
# connection is a literal '+'. Modelling this is what caught the missing
# hello byte in r0gdb-dump.ps1.
$hello = New-Object byte[] 1
$null = $stream.Read($hello, 0, 1)
if ([char]$hello[0] -ne '+') {
    Write-Host "[mock] client did not send plus first -- real stub would have died"
    $client.Close(); $listener.Stop()
    return
}
Write-Host "[mock] got plus handshake"

function Send-Packet([string]$payload) {
  $pkt = '$' + $payload + '#' + ('{0:x2}' -f (Get-Checksum $payload))
  $b = [Text.Encoding]::ASCII.GetBytes($pkt)
  $stream.Write($b, 0, $b.Length)
  $stream.Flush()
}

while ($true) {
  $sb = New-Object Text.StringBuilder
  $state = "seek"; $csumRead = 0
  $closed = $false

  while ($true) {
    $b = New-Object byte[] 1
    $n = $stream.Read($b, 0, 1)
    if ($n -le 0) { $closed = $true; break }
    $ch = [char]$b[0]
    switch ($state) {
      "seek" { if ($ch -eq '$') { $state = "body" } }
      "body" { if ($ch -eq '#') { $state = "csum" } else { [void]$sb.Append($ch) } }
      "csum" { $csumRead++; if ($csumRead -ge 2) { break } }
    }
    if ($csumRead -ge 2) { break }
  }

  if ($closed) { break }
  $req = $sb.ToString()

  if ($req -like "qSupported*") {
    Send-Packet "PacketSize=1000"
  } elseif ($req -eq "QStartNoAckMode") {
    $ack = [Text.Encoding]::ASCII.GetBytes("+")
    $stream.Write($ack, 0, 1); $stream.Flush()
  } elseif ($req -match '^m([0-9a-fA-F]+),([0-9a-fA-F]+)$') {
    $addr = [Convert]::ToUInt64($matches[1], 16)
    $len  = [Convert]::ToUInt32($matches[2], 16)
    $hex = New-Object Text.StringBuilder
    for ($i = 0; $i -lt $len; $i++) {
      [void]$hex.Append((Get-Byte ($addr + $i)).ToString('x2'))
    }
    Send-Packet $hex.ToString()
  } else {
    Send-Packet ""
  }
}

$client.Close(); $listener.Stop()
Write-Host "[mock] client disconnected"
