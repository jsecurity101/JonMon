# Deploy JonMon in Azure

[![Open_Threat_Research Community](https://img.shields.io/badge/Open_Threat_Research-Community-brightgreen.svg)](https://twitter.com/OTR_Community)
[![Open Source Love](https://badges.frapsoft.com/os/v3/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

## Deploy an Azure VM with Hyper-V Server Installed

Click on the button below to deploy an environment, provide a `username` and `password`, and select the `Azure Bastion` option to connect to the environment. Deployment takes around `20 minutes`.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FOTRF%2FBlacksmith%2Fmaster%2Ftemplates%2Fazure%2FWin-Server-HyperV%2Fazuredeploy.json)

![](images/00-ARM-Template-Deploy-Properties.png)

## Create Windows 10 Installation Media

* Connect to the Windows server via `Azure Bastion Host`
* Open PowerShell as an Administrator and run the following `PowerShell` commands to download the `MediaCreationTool`

```PowerShell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
$url = 'https://go.microsoft.com/fwlink/?LinkId=691209' 
$request = [System.Net.WebRequest]::Create($url) 
$response = $request.GetResponse() 
 
$realUrl = $response.ResponseUri.OriginalString 
$OutputFile = [System.IO.Path]::GetFileName($realUrl) 
$response.Close() 
 
$File = "C:\ProgramData\$OutputFile" 
$wc = new-object System.Net.WebClient 
$wc.DownloadFile($realUrl, $File)
```

* Double-click on the `MediaCreationTool.exe` executable located in `C:\ProgramData` and `Accept` the license terms

![](images/01-MediaCreationTool-GettingReady.png)

![](images/02-MediaCreationTool-AcceptTerms.png)

* Select `Create Installation media (USB flash drive, DVD, or ISO file) for another PC`

![](images/03-MediaCreationTool-CreateInstallationMedia.png)

* Select `language`, `architecture`, and `edition`

![](images/04-MediaCreationTool-CreateInstallationMedia-SelectLanguage.png)

* Choose media type `ISO file`

![](images/05-MediaCreationTool-CreateInstallationMedia-ChooseISOMedia.png)

* Choose where to save the file

![](images/06-MediaCreationTool-CreateInstallationMedia-SaveToFile.png)

* Download file

![](images/07-MediaCreationTool-CreateInstallationMedia-DownloadingFile.png)

## Create Hyper-V Environment

### Set Up Network

I use the [official script](https://aka.ms/azlabs/scripts/hyperV-powershell) from [Azure Lab Services](https://learn.microsoft.com/en-us/azure/lab-services/lab-services-overview) to create a create a basic Hyper-V network.

```PowerShell
Set-Location C:\ProgramData

Invoke-WebRequest 'https://aka.ms/azlabs/scripts/hyperV-powershell' -Outfile SetupForNestedVirtualization.ps1 

.\SetupForNestedVirtualization.ps1 
```

![](images/08-HyperV-CreateNetwork.png)

### Create Hyper-V Virtual Machine

On the same privileged PowerShell session, run the following commands: 

```PowerShell
$VM = "Win10-JonMon" 
$Switch = "LabServicesSwitch" 
$ISOFile = "C:\ProgramData\Windows.iso" 
$VMPath = "C:\Programdata\$VM" 
$VHD = "$VMPath\$VM.vhdx" 

New-VM -Name $VM -MemoryStartupBytes 4GB -Path $VMPath -NewVHDPath $VHD -NewVHDSizeBytes 60GB -Generation 2 -SwitchName $Switch 
```

### Mount ISO File

On the same privileged PowerShell session run the following command:

```PowerShell
Add-VMDvdDrive -VMName $VM -Path $ISOFile
```

### Configure VM Boot Order and Disable Secure Boot

```PowerShell
Set-VMFirmware -VMName $VM -BootOrder $(Get-VMDvdDrive -VMName $VM), $(Get-VMHardDiskDrive -VMName $VM), $(Get-VMNetworkAdapter -VMName $VM) -EnableSecureBoot Off
```

### Start Hyper-V and Start Windows 10 Virtual Machine

![](images/08-HyperV-Home.png)

![](images/09-HyperV-Start-VM.png)

![](images/10-HyperV-ConnectTo-VM.png)

If for some reason, the boot screen does not let you press any keys for the ISO to load, you can click on Action > Reset and it should work:

![](images/11-HyperV-Reset-InCase.png)

## Install Windows

![](images/12-HyperV-Windows-Installation.png)

![](images/13-HyperV-Windows-Installation-Now.png)

Select the `I don't have a product key` for now

![](images/14-HyperV-Windows-Installation-Skip-ProductKey.png)

Select `Windows 10 Pro` > `Next`

![](images/15-HyperV-Windows-Installation-Select-Win10Pro.png)

Accept License

![](images/16-HyperV-Windows-Installation-Accept-Terms.png)

Select `Install Windows Only (advanced)`

![](images/17-HyperV-Windows-Installation-Custom-Install.png)

Select the drive where to install Windows

![](images/18-HyperV-Windows-Installation-Drive-Selection.png)

Wait for the installation to complete

![](images/19-HyperV-Windows-Installation-Installing-Windows.png)

Finish the installation of Windows 10 according to your needs

![](images/20-HyperV-Windows-Installation-Select-Language.png)

![](images/21-HyperV-Windows-Installation-User.png)

## Turn TESTSIGNING On

Open `cmd.exe` as `Administrator` and restart Hyper-V Win10 VM

```
bcdedit /set TESTSIGNING on
```

![](images/22-HyperV-Windows-TESTSIGNING-On.png)

## Enable Internet Connection on VM

By default, our Hyper-V VM will not be connected to the Internet and since `WinNAT` by itself does not allocate and assign IP addresses to an endpoint (e.g. VM), we need to do this manually from within the VM itself - i.e. set IP address within range of NAT internal prefix, set default gateway IP address, set DNS server information.

![](images/23-HyperV-Windows-EnableNetwork.png)

After that you will be able to browse the Internet :)

![](images/24-HyperV-Windows-TestInternet.png)

## Install JonMon Service

Open `PowerShell` as `Administrator` and run the following commands to run a [Blacksmith script](https://github.com/OTRF/Blacksmith/blob/master/resources/scripts/powershell/endpoint-software/Install-JonMon.ps1) created by the community to install `JonMon` directly from its latest release.

```PowerShell
(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/OTRF/Blacksmith/master/resources/scripts/powershell/endpoint-software/Install-JonMon.ps1") | IEX
```

![](images/25-HyperV-Windows-JonMon-ServiceInstalled.png)

![](images/26-HyperV-Windows-JonMon-EventLogSample.png)

## Basic Test

I highly recommend to go over [Jonny's presentation "Unleashing JonMon"](https://github.com/jsecurity101/Presentations/blob/main/JonMon.pdf) for a few examples.

In my basic test, I wanted to see what [Sliver - GetSystem](https://github.com/BishopFox/sliver) looked like in JonMon events.

![](images/27-HyperV-Windows-JonMon-SliverGetSystem.png)


## References:

* https://github.com/Azure/azure-quickstart-templates/tree/master/demos/nested-vms-in-virtual-network
* https://github.com/jsecurity101/Presentations/blob/main/JonMon.pdf