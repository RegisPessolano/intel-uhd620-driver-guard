#requires -RunAsAdministrator
<#
.SYNOPSIS
  Protege a Intel UHD Graphics 620 contra downgrades do Windows Update.

.DESCRIPTION
  Script específico para este notebook Lenovo com:
    PCI\VEN_8086&DEV_5917&SUBSYS_39B017AA

  Fluxo esperado após uma formatação:
    1) Atualize o Windows normalmente.
    2) Instale o driver Intel oficial mais recente.
    3) Execute este script como Administrador.

  O script:
    - Detecta a versão ATUAL do driver Intel UHD 620 e usa essa versão como piso.
    - Recusa continuar se o driver instalado for anterior a 31.0.101.2141.
    - Aplica configurações best-effort para reduzir aquisição automática de drivers.
    - Oculta no Windows Update todos os drivers Intel DISPLAY inferiores ao driver instalado.
    - Oculta também os pacotes conhecidos que já causaram o downgrade nesta máquina.
    - Repete a varredura para capturar candidatos antigos que aparecem em cascata.
    - Instala uma tarefa agendada de proteção, por padrão, para repetir a checagem no logon e diariamente.
    - É idempotente: pode ser executado várias vezes.

  Observação:
    As chaves de política de exclusão de drivers não são oficialmente suportadas em todas as edições Home.
    A proteção principal deste script é o "hide" dos updates via Windows Update Agent (WUA).

.PARAMETER GuardOnly
  Executa somente a proteção/varredura. Usado pela tarefa agendada.

.PARAMETER NoScheduledTask
  Não instala/atualiza a tarefa agendada.

.PARAMETER UninstallGuard
  Remove a tarefa agendada e a cópia persistente do script.
  Não torna visíveis novamente updates já ocultados.

.EXAMPLE
  powershell.exe -ExecutionPolicy Bypass -File .\Protect-IntelUHD620.ps1

.EXAMPLE
  powershell.exe -ExecutionPolicy Bypass -File .\Protect-IntelUHD620.ps1 -NoScheduledTask

.EXAMPLE
  powershell.exe -ExecutionPolicy Bypass -File .\Protect-IntelUHD620.ps1 -UninstallGuard
#>

[CmdletBinding()]
param(
    [switch]$GuardOnly,
    [switch]$NoScheduledTask,
    [switch]$UninstallGuard
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ----------------------------
# Configuração desta máquina
# ----------------------------
$TargetInstancePrefix   = 'PCI\VEN_8086&DEV_5917&SUBSYS_39B017AA'
$MinimumAcceptedVersion = [version]'31.0.101.2141'

# Updates que já foram confirmados como problemáticos nesta máquina.
$KnownBadUpdateIds = @(
    'c70302e4-5b08-4fc3-8a5a-0c95e3653da0', # Intel Extension 25.20.100.6519
    '686c0dca-66a5-4605-9943-88a84ff81304', # Intel Display   25.20.100.6519
    '391cb60e-95e0-4655-8b00-ca2a79d43627'  # Intel Display   24.20.100.6292
)

$KnownBadVersions = @(
    '25.20.100.6519',
    '24.20.100.6292'
)

$TaskName        = 'Intel UHD 620 Driver Guard'
$InstallDir      = Join-Path $env:ProgramData 'IntelDriverGuard'
$InstalledScript = Join-Path $InstallDir 'Protect-IntelUHD620.ps1'
$LogFile         = Join-Path $InstallDir 'IntelDriverGuard.log'

function Test-IsAdministrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','OK','WARN','ERROR')][string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] [$Level] $Message"

    if (-not (Test-Path $InstallDir)) {
        New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
    }

    Add-Content -Path $LogFile -Value $line -Encoding UTF8

    switch ($Level) {
        'OK'    { Write-Host $line -ForegroundColor Green }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
}

function Get-TargetIntelDriver {
    # Preferência: dispositivo exato deste notebook.
    $drivers = Get-CimInstance Win32_PnPSignedDriver |
        Where-Object {
            $_.DeviceID -and
            $_.DeviceID.StartsWith($TargetInstancePrefix, [System.StringComparison]::OrdinalIgnoreCase)
        }

    if (-not $drivers) {
        Write-Log "Não encontrei o DeviceID exato $TargetInstancePrefix. Tentando fallback por nome." 'WARN'

        $drivers = Get-CimInstance Win32_PnPSignedDriver |
            Where-Object {
                $_.DeviceName -match 'Intel\(R\).*UHD Graphics 620|Intel.*UHD Graphics 620'
            }
    }

    $driver = $drivers |
        Where-Object { $_.DriverVersion } |
        Sort-Object @{ Expression = { try { [version]$_.DriverVersion } catch { [version]'0.0.0.0' } }; Descending = $true } |
        Select-Object -First 1

    return $driver
}

function Set-DriverUpdateProtectionRegistry {
    Write-Log 'Aplicando configurações locais de proteção contra drivers do Windows Update...'

    # "Não incluir drivers em atualizações de qualidade" (best-effort no Home)
    $wuPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    New-Item -Path $wuPolicy -Force | Out-Null
    New-ItemProperty -Path $wuPolicy `
        -Name 'ExcludeWUDriversInQualityUpdate' `
        -PropertyType DWord -Value 1 -Force | Out-Null

    # Device Installation Settings / busca automática de drivers
    $driverSearching = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching'
    New-Item -Path $driverSearching -Force | Out-Null
    New-ItemProperty -Path $driverSearching `
        -Name 'SearchOrderConfig' `
        -PropertyType DWord -Value 0 -Force | Out-Null

    # Estado observado pelo cliente moderno do Windows Update (best-effort no Home)
    $policyState = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState'
    New-Item -Path $policyState -Force | Out-Null
    New-ItemProperty -Path $policyState `
        -Name 'ExcludeWUDrivers' `
        -PropertyType DWord -Value 1 -Force | Out-Null

    Write-Log 'Configurações de Registro aplicadas.' 'OK'
}

function Get-VersionFromUpdateTitle {
    param([string]$Title)

    if ($Title -match '(\d+\.\d+\.\d+\.\d+)\s*$') {
        try {
            return [version]$Matches[1]
        }
        catch {
            return $null
        }
    }

    return $null
}

function Hide-OldIntelGraphicsUpdates {
    param(
        [Parameter(Mandatory=$true)][version]$CurrentVersion
    )

    Write-Log "Usando $CurrentVersion como versão mínima protegida."

    $maxPasses = 30
    $totalHidden = 0

    for ($pass = 1; $pass -le $maxPasses; $pass++) {
        Write-Log "Varredura Windows Update $pass/$maxPasses..."

        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result   = $searcher.Search('IsInstalled=0 and IsHidden=0')

        $hiddenThisPass = 0

        for ($i = 0; $i -lt $result.Updates.Count; $i++) {
            $u = $result.Updates.Item($i)

            $title    = [string]$u.Title
            $updateId = [string]$u.Identity.UpdateID
            $version  = Get-VersionFromUpdateTitle -Title $title

            $isIntelDisplay   = $title -match '^Intel Corporation - Display - '
            $isIntelExtension = $title -match '^Intel Corporation - Extension - '

            if (-not ($isIntelDisplay -or $isIntelExtension)) {
                continue
            }

            $isKnownBadId = $KnownBadUpdateIds -contains $updateId
            $isKnownBadVersion = $false

            if ($version) {
                $isKnownBadVersion = $KnownBadVersions -contains $version.ToString()
            }

            # Regra principal:
            # - DISPLAY Intel com versão menor que a atualmente instalada: ocultar.
            # - EXTENSION: ocultar somente se for um pacote já conhecido como ruim
            #   nesta máquina, para não atingir extensões Intel não relacionadas.
            $shouldHide = $false

            if ($isKnownBadId) {
                $shouldHide = $true
            }
            elseif ($isIntelDisplay -and $version -and ($version -lt $CurrentVersion)) {
                $shouldHide = $true
            }
            elseif ($isIntelExtension -and $isKnownBadVersion) {
                $shouldHide = $true
            }

            if ($shouldHide) {
                try {
                    Write-Log "Ocultando: $title | UpdateID=$updateId" 'WARN'
                    $u.IsHidden = $true

                    if ($u.IsHidden) {
                        Write-Log "Ocultado com sucesso: $title" 'OK'
                        $hiddenThisPass++
                        $totalHidden++
                    }
                    else {
                        Write-Log "WUA não confirmou IsHidden=True para: $title" 'ERROR'
                    }
                }
                catch {
                    Write-Log "Falha ao ocultar '$title': $($_.Exception.Message)" 'ERROR'
                }
            }
        }

        if ($hiddenThisPass -eq 0) {
            Write-Log 'Nenhum outro downgrade Intel visível nesta varredura.' 'OK'
            break
        }

        # Uma nova sessão pode revelar o próximo candidato antigo.
        Start-Sleep -Seconds 3
    }

    Write-Log "Total de updates ocultados nesta execução: $totalHidden"

    # Verificação final
    $session2  = New-Object -ComObject Microsoft.Update.Session
    $searcher2 = $session2.CreateUpdateSearcher()
    $result2   = $searcher2.Search('IsInstalled=0 and IsHidden=0')

    $remaining = @()

    for ($i = 0; $i -lt $result2.Updates.Count; $i++) {
        $u = $result2.Updates.Item($i)
        $title = [string]$u.Title

        if ($title -notmatch '^Intel Corporation - Display - ') {
            continue
        }

        $version = Get-VersionFromUpdateTitle -Title $title

        if ($version -and ($version -lt $CurrentVersion)) {
            $remaining += [PSCustomObject]@{
                Title    = $title
                UpdateID = $u.Identity.UpdateID
                Version  = $version.ToString()
            }
        }
    }

    if ($remaining.Count -eq 0) {
        Write-Log 'VERIFICAÇÃO FINAL: nenhum Intel Display inferior ao driver atual está visível.' 'OK'
        return $true
    }

    Write-Log 'VERIFICAÇÃO FINAL: ainda existem downgrades Intel visíveis:' 'ERROR'
    $remaining | Format-Table -AutoSize | Out-String | ForEach-Object {
        if ($_.Trim()) { Write-Log $_.TrimEnd() 'ERROR' }
    }

    return $false
}

function Install-DriverGuardTask {
    if ($NoScheduledTask -or $GuardOnly) {
        return
    }

    Write-Log 'Instalando proteção persistente no Agendador de Tarefas...'

    if (-not $PSCommandPath -or -not (Test-Path $PSCommandPath)) {
        Write-Log 'Não foi possível determinar o caminho do script. A tarefa agendada não será criada.' 'WARN'
        return
    }

    if (-not (Test-Path $InstallDir)) {
        New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
    }

    # Evita copiar o arquivo sobre ele mesmo.
    if ([IO.Path]::GetFullPath($PSCommandPath) -ne [IO.Path]::GetFullPath($InstalledScript)) {
        Copy-Item -Path $PSCommandPath -Destination $InstalledScript -Force
    }

    $powershellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$InstalledScript`" -GuardOnly"

    $action = New-ScheduledTaskAction `
        -Execute $powershellExe `
        -Argument $arguments

    # Checa a cada logon e novamente uma vez por dia.
    $triggerLogon = New-ScheduledTaskTrigger -AtLogOn
    $triggerDaily = New-ScheduledTaskTrigger -Daily -At '12:00'

    $principal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest

    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger @($triggerLogon, $triggerDaily) `
        -Principal $principal `
        -Settings $settings `
        -Description 'Impede downgrades do driver Intel UHD Graphics 620 pelo Windows Update.' `
        -Force | Out-Null

    Write-Log "Tarefa agendada '$TaskName' instalada/atualizada." 'OK'
    Write-Log "Cópia persistente: $InstalledScript"
}

function Uninstall-DriverGuard {
    Write-Host "Removendo proteção persistente..." -ForegroundColor Yellow

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {}

    try {
        if (Test-Path $InstallDir) {
            Remove-Item -Path $InstallDir -Recurse -Force
        }
    }
    catch {}

    Write-Host "Tarefa/cópia persistente removidas." -ForegroundColor Green
    Write-Host "Observação: updates já marcados como Hidden NÃO foram reexibidos."
}

# ----------------------------
# Execução
# ----------------------------
if (-not (Test-IsAdministrator)) {
    throw 'Execute este script em PowerShell/Terminal COMO ADMINISTRADOR.'
}

if ($UninstallGuard) {
    Uninstall-DriverGuard
    exit 0
}

Write-Log '============================================================'
Write-Log 'Intel UHD 620 Driver Guard iniciado.'

$driver = Get-TargetIntelDriver

if (-not $driver) {
    Write-Log 'Intel UHD Graphics 620 não encontrada. Nenhuma alteração será feita.' 'ERROR'
    exit 2
}

try {
    $currentVersion = [version]$driver.DriverVersion
}
catch {
    Write-Log "Não foi possível interpretar a versão instalada: $($driver.DriverVersion)" 'ERROR'
    exit 3
}

Write-Log "GPU: $($driver.DeviceName)"
Write-Log "DeviceID: $($driver.DeviceID)"
Write-Log "INF instalado: $($driver.InfName)"
Write-Log "Driver atual: $currentVersion"

if ($currentVersion -lt $MinimumAcceptedVersion) {
    Write-Log "ABORTADO: o driver atual ($currentVersion) é anterior ao mínimo aceito ($MinimumAcceptedVersion)." 'ERROR'
    Write-Log 'Instale primeiro o driver Intel oficial mais recente e execute o script novamente.' 'ERROR'
    exit 4
}

Set-DriverUpdateProtectionRegistry

$success = Hide-OldIntelGraphicsUpdates -CurrentVersion $currentVersion

if ($success) {
    Install-DriverGuardTask
    Write-Log "PROTEÇÃO ATIVA. Driver $currentVersion preservado." 'OK'
    Write-Log "Log: $LogFile"
    exit 0
}
else {
    Write-Log 'Proteção aplicada parcialmente; revise o log antes de permitir o Windows Update instalar drivers.' 'ERROR'
    exit 5
}
