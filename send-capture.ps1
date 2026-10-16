# Send a payload to elfldr and capture the payload's stdout to a file.
#
# NetCat GUIs do not display the data they receive, which makes every
# diagnostic in this repo invisible. The payload's printf output comes
# back over the SAME TCP connection used to send it, so a plain
# send-then-read captures it.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File send-capture.ps1 `
#       -Console 192.168.1.50 -Payload .\byepervisor_stageB_0860.elf `
#       -Out stageB.log -Seconds 180
param(
  [Parameter(Mandatory=$true)][string]$Console,
  [Parameter(Mandatory=$true)][string]$Payload,
  [string]$Out = "payload.log",
  [int]$Port = 9021,
  [int]$Seconds = 180
)

$ErrorActionPreference = "Stop"
$bytes = [IO.File]::ReadAllBytes($Payload)
Write-Host "[send] $Payload ($($bytes.Length) bytes) -> $Console`:$Port"

$client = New-Object Net.Sockets.TcpClient
$client.Connect($Console, $Port)
$stream = $client.GetStream()

$stream.Write($bytes, 0, $bytes.Length)
$stream.Flush()
Write-Host "[send] payload delivered; switching to receive"

# Signal end-of-send so the loader knows the ELF is complete.
try { $client.Client.Shutdown([Net.Sockets.SocketShutdown]::Send) } catch {}

$stream.ReadTimeout = 2000
$deadline = (Get-Date).AddSeconds($Seconds)
$sb = New-Object Text.StringBuilder
$total = 0

while ((Get-Date) -lt $deadline) {
  $buf = New-Object byte[] 65536
  try {
    $n = $stream.Read($buf, 0, $buf.Length)
  } catch [System.IO.IOException] {
    continue   # read timeout: no data yet, keep waiting
  } catch {
    break
  }
  if ($n -le 0) { break }
  $total += $n
  $chunk = [Text.Encoding]::UTF8.GetString($buf, 0, $n)
  [void]$sb.Append($chunk)
  Write-Host -NoNewline $chunk
}

$client.Close()
Set-Content -Path $Out -Value $sb.ToString() -Encoding UTF8
Write-Host ""
Write-Host "[recv] $total bytes captured -> $Out"
if ($total -eq 0) {
  Write-Warning "No data received. Either the payload never started, or the loader did not relay stdout."
}


