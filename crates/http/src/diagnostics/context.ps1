$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
function Read-Source($source,$query) {
    try { @{source=$source;status='available';data=@(& $query)} }
    catch { @{source=$source;status='error';error=$_.Exception.Message;data=$null} }
}
$driverByDevice=@{}
$driverSource=Read-Source 'Win32_PnPSignedDriver' {
    Get-CimInstance Win32_PnPSignedDriver | ForEach-Object {
        $driverByDevice[$_.DeviceID]=@{name=$_.DriverName;version=$_.DriverVersion;provider=$_.DriverProviderName;date=$(if($_.DriverDate){$_.DriverDate.ToUniversalTime().ToString('o')}else{$null})}
    }
}
function Read-Driver($id) { if($null -eq $id){return $null}; $driverByDevice[$id] }
$result=[ordered]@{}
$result.windows=Read-Source 'CurrentVersion registry; Win32_OperatingSystem' {
    $version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os=Get-CimInstance Win32_OperatingSystem
    @{edition=$version.EditionID;display_version=$version.DisplayVersion;build=$version.CurrentBuildNumber;ubr=$version.UBR;version=$os.Version;architecture=$os.OSArchitecture;last_boot_utc=$os.LastBootUpTime.ToUniversalTime().ToString('o')}
}
$result.cpu=Read-Source 'Win32_Processor' {
    Get-CimInstance Win32_Processor | ForEach-Object {
        @{id=$_.DeviceID;manufacturer=$_.Manufacturer;model=$_.Name;architecture=$_.Architecture;family=$_.Family;stepping=$_.Stepping;revision=$_.Revision;cores=$_.NumberOfCores;logical_processors=$_.NumberOfLogicalProcessors}
    }
}
$result.virtualization=Read-Source 'Win32_ComputerSystem' {
    $computer=Get-CimInstance Win32_ComputerSystem
    @{manufacturer=$computer.Manufacturer;model=$computer.Model;hypervisor_present=$computer.HypervisorPresent;physical_or_vm=$null}
}
$result.security=Read-Source 'Win32_DeviceGuard' {
    $guard=Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard
    @{vbs_status=$guard.VirtualizationBasedSecurityStatus;security_services_configured=@($guard.SecurityServicesConfigured);security_services_running=@($guard.SecurityServicesRunning);hvci_running=(@($guard.SecurityServicesRunning) -contains 2)}
}
$result.gpus=Read-Source 'Win32_VideoController' {
    Get-CimInstance Win32_VideoController | ForEach-Object {
        @{id=$_.DeviceID;model=$_.Name;driver_version=$_.DriverVersion;driver=(Read-Driver $_.PNPDeviceID);status=$_.Status}
    }
}
$result.disks=Read-Source 'Win32_DiskDrive' {
    Get-CimInstance Win32_DiskDrive | ForEach-Object {
        @{id="disk:$($_.Index)";index=$_.Index;model=$_.Model;interface_type=$_.InterfaceType;size_bytes=$_.Size;driver=(Read-Driver $_.PNPDeviceID);status=$_.Status}
    }
}
$result.network=Read-Source 'Win32_NetworkAdapter' {
    Get-CimInstance Win32_NetworkAdapter | Where-Object {$null -ne $_.InterfaceIndex} | ForEach-Object {
        @{id="interface:$($_.InterfaceIndex)";interface_index=$_.InterfaceIndex;description=$_.Description;adapter_type=$_.AdapterType;physical=$_.PhysicalAdapter;speed_bps=$_.Speed;driver=(Read-Driver $_.PNPDeviceID);status=$_.Status}
    }
}
$result.storage=Read-Source 'MSFT_Disk' {
    Get-CimInstance -Namespace root/Microsoft/Windows/Storage -ClassName MSFT_Disk | ForEach-Object {
        @{id="disk:$($_.Number)";number=$_.Number;model=$_.FriendlyName;bus_type=$_.BusType;size_bytes=$_.Size;logical_sector_bytes=$_.LogicalSectorSize;physical_sector_bytes=$_.PhysicalSectorSize}
    }
}
$result.driver_query=$driverSource
$result.temperature_driver=Read-Source 'Win32_SystemDriver: PawnIO/WinRing0' {
    Get-CimInstance Win32_SystemDriver -Filter "Name='PawnIO' OR Name LIKE 'WinRing0%'" | ForEach-Object {
        @{name=$_.Name;state=$_.State;status=$_.Status;start_mode=$_.StartMode;path=$_.PathName;file_version=$(if(Test-Path -LiteralPath $_.PathName){(Get-Item -LiteralPath $_.PathName).VersionInfo.FileVersion}else{$null})}
    }
}
$result.backend=Read-Source 'Deployed temperature backend files' {
    $root=Split-Path (Get-Process -Id $env:UNIPROC_DIAGNOSTIC_SERVICE_PID).Path
    foreach($file in @('uniproc-lhm.dll','PawnIO.dll','LibreHardwareMonitorLib.dll')) {
        $path=Join-Path $root $file
        if(Test-Path -LiteralPath $path) {
            $item=Get-Item -LiteralPath $path
            @{file=$file;file_version=$item.VersionInfo.FileVersion;product_version=$item.VersionInfo.ProductVersion;bytes=$item.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
        }
    }
}
$result | ConvertTo-Json -Depth 15 -Compress
