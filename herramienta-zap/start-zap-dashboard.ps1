param(
  [string[]]$AllowedHosts = @("localhost", "127.0.0.1", "host.docker.internal"),
  [int]$Port = 8787
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dashboardPath = Join-Path $root "zap-dashboard.html"
$reportPath = Join-Path $root "zap-report.json"
$runsPath = Join-Path $root "scan-runs"
$allowed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($hostName in $AllowedHosts) {
  foreach ($entry in ([string]$hostName -split "[,;]")) {
    $normalizedHost = $entry.Trim().TrimEnd(".")
    if ($normalizedHost) { [void]$allowed.Add($normalizedHost) }
  }
}

if (-not (Test-Path -LiteralPath $dashboardPath)) { throw "No se encontró zap-dashboard.html junto a este script." }
if (-not (Test-Path -LiteralPath $reportPath)) {
  [System.IO.File]::WriteAllText($reportPath, '{"site":[]}', [System.Text.UTF8Encoding]::new($false))
}
New-Item -ItemType Directory -Force -Path $runsPath | Out-Null

$jobs = @{}
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
try {
  $listener.Start()
} catch {
  throw "No se pudo abrir http://127.0.0.1:$Port/. Prueba otro puerto con -Port 8788. Detalle: $($_.Exception.Message)"
}

function Send-Bytes($Connection, [int]$Status, [string]$ContentType, [byte[]]$Bytes, [string]$ExtraHeaders = "") {
  $reason = switch ($Status) {
    200 { "OK" } 202 { "Accepted" } 400 { "Bad Request" } 403 { "Forbidden" }
    404 { "Not Found" } 409 { "Conflict" } 500 { "Internal Server Error" }
    default { "OK" }
  }
  $header = "HTTP/1.1 $Status $reason`r`nContent-Type: $ContentType`r`nContent-Length: $($Bytes.Length)`r`nCache-Control: no-store`r`nX-Content-Type-Options: nosniff`r`n${ExtraHeaders}Connection: close`r`n`r`n"
  $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
  $Connection.Stream.Write($headerBytes, 0, $headerBytes.Length)
  if ($Bytes.Length -gt 0) { $Connection.Stream.Write($Bytes, 0, $Bytes.Length) }
  $Connection.Stream.Flush()
}

function Send-Json($Connection, [int]$Status, $Value) {
  $json = ConvertTo-Json -InputObject $Value -Depth 100 -Compress
  Send-Bytes $Connection $Status "application/json; charset=utf-8" ([System.Text.Encoding]::UTF8.GetBytes($json))
}

function Read-Request($Client) {
  $stream = $Client.GetStream()
  $stream.ReadTimeout = 10000
  $headerBytes = [System.Collections.Generic.List[byte]]::new()
  while ($true) {
    $value = $stream.ReadByte()
    if ($value -lt 0) { throw "Conexión cerrada antes de recibir la solicitud." }
    $headerBytes.Add([byte]$value)
    $length = $headerBytes.Count
    if ($length -ge 4 -and $headerBytes[$length - 4] -eq 13 -and $headerBytes[$length - 3] -eq 10 -and $headerBytes[$length - 2] -eq 13 -and $headerBytes[$length - 1] -eq 10) { break }
    if ($length -gt 16384) { throw "Encabezados HTTP demasiado grandes." }
  }

  $headerText = [System.Text.Encoding]::ASCII.GetString($headerBytes.ToArray())
  $lines = $headerText -split "`r`n"
  $requestLine = $lines[0].Split(" ")
  if ($requestLine.Length -lt 2) { throw "Solicitud HTTP no válida." }
  $headers = @{}
  foreach ($line in $lines | Select-Object -Skip 1) {
    $separator = $line.IndexOf(":")
    if ($separator -gt 0) { $headers[$line.Substring(0, $separator).Trim().ToLowerInvariant()] = $line.Substring($separator + 1).Trim() }
  }
  $contentLength = 0
  if ($headers.ContainsKey("content-length")) { $contentLength = [int]$headers["content-length"] }
  if ($contentLength -gt 1048576) { throw "La solicitud excede el tamaño permitido." }
  $bodyBytes = [byte[]]::new($contentLength)
  $offset = 0
  while ($offset -lt $contentLength) {
    $read = $stream.Read($bodyBytes, $offset, $contentLength - $offset)
    if ($read -le 0) { throw "Cuerpo HTTP incompleto." }
    $offset += $read
  }
  $target = [System.Uri]::new("http://127.0.0.1:$Port$($requestLine[1])")
  return @{
    Method = $requestLine[0].ToUpperInvariant(); Path = $target.AbsolutePath;
    Headers = $headers; Body = [System.Text.Encoding]::UTF8.GetString($bodyBytes)
  }
}

function Get-JobResponse($Job) {
  if ($Job.Status -eq "running" -and $Job.Process.HasExited -and -not $Job.Finalized) {
    $Job.Finalized = $true
    $Job.Process.WaitForExit()
    if (Test-Path -LiteralPath $Job.ReportPath) {
      try {
        $reportJson = [System.IO.File]::ReadAllText($Job.ReportPath, [System.Text.Encoding]::UTF8)
        $Job.Report = ConvertFrom-Json -InputObject $reportJson
        Copy-Item -LiteralPath $Job.ReportPath -Destination $reportPath -Force
        $Job.Status = "complete"
      } catch {
        $Job.Status = "error"
        $Job.Error = "ZAP generó un archivo que no se pudo leer: $($_.Exception.Message)"
      }
    } else {
      $Job.Status = "error"
      $Job.Error = "ZAP terminó sin generar el informe (código $($Job.Process.ExitCode)). Revisa la salida de Docker en esta PowerShell."
    }
    $Job.Process.Dispose()
  }

  if ($Job.Status -eq "running") {
    return @{ id = $Job.Id; status = "running"; target = $Job.Target; profile = $Job.Profile; message = "ZAP ejecuta el perfil $($Job.ProfileLabel) con análisis pasivo. Esto puede tardar unos minutos." }
  }
  if ($Job.Status -eq "complete") {
    return @{ id = $Job.Id; status = "complete"; target = $Job.Target; profile = $Job.Profile; profileLabel = $Job.ProfileLabel; report = $Job.Report }
  }
  return @{ id = $Job.Id; status = "error"; target = $Job.Target; profile = $Job.Profile; error = $Job.Error }
}

function Test-LocalOrigin([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
  $originUri = $null
  if (-not [System.Uri]::TryCreate($Value, [System.UriKind]::Absolute, [ref]$originUri)) { return $false }
  return $originUri.Scheme -eq "http" -and $originUri.DnsSafeHost -in @("127.0.0.1", "localhost") -and $originUri.Port -eq $Port -and -not $originUri.UserInfo
}

function Test-LocalHostHeader([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
  $hostUri = $null
  if (-not [System.Uri]::TryCreate("http://$Value", [System.UriKind]::Absolute, [ref]$hostUri)) { return $false }
  return $hostUri.DnsSafeHost -in @("127.0.0.1", "localhost") -and $hostUri.Port -eq $Port -and -not $hostUri.UserInfo
}

Write-Host "Dashboard ZAP listo en http://127.0.0.1:$Port/" -ForegroundColor Green
Write-Host "Hosts permitidos: $(@($allowed | Sort-Object) -join ', ')"
Write-Host "Deja esta ventana abierta mientras usas el dashboard. Pulsa Ctrl+C para detenerlo."

try {
  while ($true) {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    try {
      $request = Read-Request $client
      if (-not (Test-LocalHostHeader $request.Headers.host)) {
        Send-Json @{ Stream = $stream } 403 @{ error = "Host HTTP no permitido. Abre el dashboard desde http://127.0.0.1:$Port/ o http://localhost:$Port/." }
        continue
      }
      $method = $request.Method
      $path = $request.Path

      if ($method -eq "GET" -and ($path -eq "/" -or $path -eq "/zap-dashboard.html")) {
        Send-Bytes @{ Stream = $stream } 200 "text/html; charset=utf-8" ([System.IO.File]::ReadAllBytes($dashboardPath))
        continue
      }
      if ($method -eq "GET" -and $path -eq "/api/config") {
        Send-Json @{ Stream = $stream } 200 @{ allowedHosts = @($allowed | Sort-Object); scanner = "OWASP ZAP Baseline" }
        continue
      }
      if ($method -eq "GET" -and $path -eq "/api/report") {
        Send-Bytes @{ Stream = $stream } 200 "application/json; charset=utf-8" ([System.IO.File]::ReadAllBytes($reportPath))
        continue
      }
      if ($method -eq "GET" -and $path -eq "/api/history") {
        $historyItems = @(
          foreach ($directory in (Get-ChildItem -LiteralPath $runsPath -Directory)) {
            if ($directory.Name -notmatch '^[a-fA-F0-9]{32}$') { continue }
            $runReportPath = Join-Path $directory.FullName "zap-report.json"
            if (-not (Test-Path -LiteralPath $runReportPath -PathType Leaf)) { continue }
            try {
              $runReport = [System.IO.File]::ReadAllText($runReportPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
              $site = @($runReport.site | Select-Object -First 1)[0]
              [pscustomobject]@{
                id = $directory.Name
                target = if ($site) { [string]$site.'@name' } else { "Objetivo no indicado" }
                created = if ($runReport.created) { [string]$runReport.created } else { $directory.LastWriteTimeUtc.ToString("o") }
                bytes = (Get-Item -LiteralPath $runReportPath).Length
              }
            } catch { }
          }
        ) | Sort-Object created -Descending
        Send-Json @{ Stream = $stream } 200 @{ reports = @($historyItems) }
        continue
      }
      if ($method -eq "GET" -and $path -match '^/api/history/([a-fA-F0-9]{32})/report$') {
        $id = $Matches[1].ToLowerInvariant()
        $runReportPath = Join-Path (Join-Path $runsPath $id) "zap-report.json"
        if (-not (Test-Path -LiteralPath $runReportPath -PathType Leaf)) {
          Send-Json @{ Stream = $stream } 404 @{ error = "No se encontró el informe solicitado." }
          continue
        }
        $bytes = [System.IO.File]::ReadAllBytes($runReportPath)
        Send-Bytes @{ Stream = $stream } 200 "application/json; charset=utf-8" $bytes "Content-Disposition: attachment; filename=`"zap-report-$id.json`"`r`n"
        continue
      }
      if ($method -eq "DELETE" -and $path -match '^/api/history/([a-fA-F0-9]{32})$') {
        if ($request.Headers.origin -and -not (Test-LocalOrigin $request.Headers.origin)) {
          Send-Json @{ Stream = $stream } 403 @{ error = "Origen HTTP no permitido." }
          continue
        }
        $id = $Matches[1].ToLowerInvariant()
        if ($jobs.ContainsKey($id) -and $jobs[$id].Status -eq "running" -and -not $jobs[$id].Process.HasExited) {
          Send-Json @{ Stream = $stream } 409 @{ error = "No se puede eliminar una ejecución todavía en curso." }
          continue
        }
        $runDirectory = Join-Path $runsPath $id
        $runReportPath = Join-Path $runDirectory "zap-report.json"
        if (-not (Test-Path -LiteralPath $runReportPath -PathType Leaf)) {
          Send-Json @{ Stream = $stream } 404 @{ error = "No se encontró ese informe en el historial." }
          continue
        }
        $resolvedRunPath = [System.IO.Path]::GetFullPath($runDirectory)
        $resolvedRunsPath = [System.IO.Path]::GetFullPath($runsPath) + [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolvedRunPath.StartsWith($resolvedRunsPath, [System.StringComparison]::OrdinalIgnoreCase)) {
          Send-Json @{ Stream = $stream } 403 @{ error = "La ruta del informe no está dentro del historial." }
          continue
        }
        Remove-Item -LiteralPath $resolvedRunPath -Recurse -Force
        Send-Json @{ Stream = $stream } 200 @{ deleted = $id }
        continue
      }
      if ($method -eq "POST" -and $path -eq "/api/scans") {
        $requestData = ConvertFrom-Json -InputObject $request.Body
        if ($request.Headers.origin -and -not (Test-LocalOrigin $request.Headers.origin)) {
          Send-Json @{ Stream = $stream } 403 @{ error = "Origen HTTP no permitido." }
          continue
        }
        if ($requestData.authorized -ne $true) {
          Send-Json @{ Stream = $stream } 400 @{ error = "Confirma que tienes autorización para analizar este objetivo." }
          continue
        }
        if ([string]::IsNullOrWhiteSpace([string]$requestData.target) -or ([string]$requestData.target).Length -gt 2048) {
          Send-Json @{ Stream = $stream } 400 @{ error = "Introduce una URL válida de hasta 2048 caracteres." }
          continue
        }
        $profile = if ([string]::IsNullOrWhiteSpace([string]$requestData.profile)) { "standard" } else { [string]$requestData.profile }
        if ($profile -notin @("standard", "extended")) {
          Send-Json @{ Stream = $stream } 400 @{ error = "El perfil de análisis solicitado no es válido." }
          continue
        }
        $spiderMinutes = if ($profile -eq "extended") { 5 } else { 2 }
        $profileLabel = if ($profile -eq "extended") { "Cobertura ampliada (5 min)" } else { "Estándar (2 min)" }

        $uri = $null
        if (-not [System.Uri]::TryCreate([string]$requestData.target, [System.UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -notin @("http", "https") -or $uri.UserInfo) {
          Send-Json @{ Stream = $stream } 400 @{ error = "Usa una URL absoluta http:// o https:// sin usuario ni contraseña." }
          continue
        }
        $hostName = $uri.DnsSafeHost.TrimEnd(".")
        if (-not $allowed.Contains($hostName)) {
          Send-Json @{ Stream = $stream } 403 @{ error = "El host '$hostName' no está permitido. Hosts habilitados: $(@($allowed | Sort-Object) -join ', ')" }
          continue
        }
        $running = @($jobs.Values | Where-Object { $_.Status -eq "running" -and -not $_.Process.HasExited })
        if ($running.Count -gt 0) {
          Send-Json @{ Stream = $stream } 409 @{ error = "Ya hay un análisis en curso. Espera a que termine antes de iniciar otro." }
          continue
        }

        $id = [guid]::NewGuid().ToString("N")
        $jobDirectory = Join-Path $runsPath $id
        New-Item -ItemType Directory -Force -Path $jobDirectory | Out-Null
        $builder = [System.UriBuilder]::new($uri)
        if ($hostName -in @("localhost", "127.0.0.1")) { $builder.Host = "host.docker.internal" }
        $zapTarget = $builder.Uri.AbsoluteUri
        $fullJobDirectory = [System.IO.Path]::GetFullPath($jobDirectory)
        $quotedTarget = $zapTarget.Replace('"', '%22')
        # Keep both profiles passive; only the traditional spider time limit changes.
        $arguments = "run --rm --mount `"type=bind,source=$fullJobDirectory,target=/zap/wrk`" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t `"$quotedTarget`" -j --client-spider -m $spiderMinutes -J zap-report.json"
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = "docker"
        $startInfo.Arguments = $arguments
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $false
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        try {
          if (-not $process.Start()) { throw "No se pudo iniciar Docker." }
        } catch {
          $process.Dispose()
          Send-Json @{ Stream = $stream } 500 @{ error = "No se pudo ejecutar Docker desde esta PowerShell: $($_.Exception.Message)" }
          continue
        }
        $jobs[$id] = @{
          Id = $id; Target = $uri.AbsoluteUri; Profile = $profile; ProfileLabel = $profileLabel; Process = $process; Status = "running";
          ReportPath = (Join-Path $jobDirectory "zap-report.json"); Report = $null;
          Error = $null; Finalized = $false
        }
        Send-Json @{ Stream = $stream } 202 @{ id = $id; status = "running"; target = $uri.AbsoluteUri; profile = $profile; profileLabel = $profileLabel }
        continue
      }
      if ($method -eq "GET" -and $path -match '^/api/scans/([a-fA-F0-9]{32})$') {
        $id = $Matches[1].ToLowerInvariant()
        if (-not $jobs.ContainsKey($id)) {
          Send-Json @{ Stream = $stream } 404 @{ error = "No se encontró ese análisis." }
          continue
        }
        Send-Json @{ Stream = $stream } 200 (Get-JobResponse $jobs[$id])
        continue
      }
      Send-Json @{ Stream = $stream } 404 @{ error = "Ruta no encontrada." }
    } catch {
      try { Send-Json @{ Stream = $stream } 500 @{ error = $_.Exception.Message } } catch { }
    } finally {
      $client.Close()
    }
  }
} finally {
  foreach ($job in $jobs.Values) {
    if ($job.Status -eq "running" -and -not $job.Process.HasExited) {
      try { $job.Process.Kill() } catch { }
    }
  }
  $listener.Stop()
}
