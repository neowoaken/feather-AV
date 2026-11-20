#Requires -Version 5.1
<#
  Minimal mock clamd. Implements just enough of the INSTREAM protocol to test
  feather's ClamAV adapter without installing ClamAV (and without GPL code in
  this repository).

  Usage: mock-clamd.ps1 -Port <n> -Signature <name> -ReadyFile <path> [-Mode found|ok]
#>
param(
    [Parameter(Mandatory)][int]$Port,
    [string]$Signature = "",
    [Parameter(Mandatory)][string]$ReadyFile,
    [ValidateSet("found", "ok")][string]$Mode = "found"
)

$ErrorActionPreference = "Stop"

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()
Set-Content -Path $ReadyFile -Value "ready" -NoNewline

try {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $stream.ReadTimeout = 5000

    # --- command, NUL-terminated ("zINSTREAM\0") --------------------------
    $command = New-Object System.Collections.Generic.List[byte]
    while ($true) {
        $b = $stream.ReadByte()
        if ($b -lt 0) { throw "client closed before NUL terminator" }
        if ($b -eq 0) { break }
        $command.Add([byte]$b)
    }
    if (-not ([System.Text.Encoding]::ASCII.GetString($command.ToArray()) -eq "zINSTREAM")) {
        throw "unexpected command"
    }

    # --- chunks: uint32 big-endian length + payload, terminated by zero ---
    $lenBuf = New-Object byte[] 4
    while ($true) {
        $read = 0
        while ($read -lt 4) {
            $n = $stream.Read($lenBuf, $read, 4 - $read)
            if ($n -le 0) { throw "eof while reading chunk length" }
            $read += $n
        }
        $length = ([int]$lenBuf[0] * 16777216) + ([int]$lenBuf[1] * 65536) + ([int]$lenBuf[2] * 256) + [int]$lenBuf[3]
        if ($length -eq 0) { break }

        $drain = New-Object byte[] 65536
        $left = $length
        while ($left -gt 0) {
            $want = [Math]::Min($left, $drain.Length)
            $n = $stream.Read($drain, 0, $want)
            if ($n -le 0) { throw "eof while reading chunk body" }
            $left -= $n
        }
    }

    # --- reply ------------------------------------------------------------
    $response = if ($Mode -eq "ok") { "stream: OK" } elseif ($Signature) { "stream: $Signature FOUND" } else { "stream: OK" }
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($response + [char]0)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
    Start-Sleep -Milliseconds 100
    $client.Close()
}
finally {
    $listener.Stop()
}
