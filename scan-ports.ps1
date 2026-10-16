# Find which port prosper0gdb bound to.
#
# The stub binds the first free port at or above 1234 and then blocks in
# accept(), so 1234 is only a starting guess: if anything already holds
# it, the stub lands on 1235, 1236, and so on.
#
# Also probes 9021, which must be open if elfldr is running. That
# separates "the network path is wrong" from "the stub never started".
#
#   powershell -ExecutionPolicy Bypass -File scan-ports.ps1 -Console 192.168.100.58

param(
  [Parameter(Mandatory=$true)][string]$Console,
  [int]$From = 1234,
  [int]$To = 1260,
  [int]$TimeoutMs = 400,
  [int[]]$Also = @(9021)
)

$ErrorActionPreference = "Continue"

function Test-Port([string]$host_, [int]$port, [int]$timeoutMs) {
  try {
    $c = New-Object Net.Sockets.TcpClient
    $iar = $c.BeginConnect($host_, $port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($timeoutMs)) { $c.Close(); return $false }
    $c.EndConnect($iar)
    $c.Close()
    return $true
  } catch {
    return $false
  }
}

Write-Host "[scan] probing $Console ..."
$open = @()

foreach ($p in $Also) {
  if (Test-Port $Console $p $TimeoutMs) {
    Write-Host ("  {0,-6} OPEN   (expected: elfldr)" -f $p)
    $open += $p
  } else {
    Write-Host ("  {0,-6} closed" -f $p)
  }
}

Write-Host "[scan] probing $From..$To for the gdb stub ..."
$openGdb = @()
for ($p = $From; $p -le $To; $p++) {
  if (Test-Port $Console $p $TimeoutMs) {
    Write-Host ("  {0,-6} OPEN   <-- possible prosper0gdb stub" -f $p)
    $openGdb += $p
  }
}

Write-Host ""
if ($openGdb.Count -gt 0) {
  Write-Host "[scan] candidate stub port(s): $($openGdb -join ', ')"
  Write-Host "[scan] retry the dump with -Port <that port>"
} else {
  Write-Host "[scan] no stub port found in $From..$To"
  if ($open -contains 9021) {
    Write-Host "[scan] elfldr IS reachable on 9021, so the network path is fine."
    Write-Host "[scan] That means kstuff.elf did not start the gdb stub."
    Write-Host "[scan] Watch the TV during load -- kstuff prints its own status."
  } else {
    Write-Host "[scan] 9021 is closed too, so nothing payload-related is running."
    Write-Host "[scan] Check the IP address and that you are on the same network."
  }
}
