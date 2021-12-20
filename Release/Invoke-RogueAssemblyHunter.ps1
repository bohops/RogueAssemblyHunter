function Invoke-RogueAssemblyHunter
{
    <#
        .SYNOPSIS
            Tool: Rogue Assembly Hunter
            Purpose: A utility for discovering 'interesting' .NET CLR modules in running processes.
            Usage:  This PowerShell script is a simple call wrapper to invoke managed executables for scanning x86 and x64 processes to find interesting .NET assemblies. 
                    For advanced usage, refer to the GitHub page or managed executable Help feature.
            Author: @bohops
            License: MIT
        .EXAMPLE
            PS C:\> Invoke-AssemblyHunter
            Wrapper for executing AssemblyHunter_x86.exe and AssemblyHunter_x64.exe in the same directory to scan 
            managed processes for interesting assemblies.
        .EXAMPLE
            PS C:\> Invoke-AssemblyHunter -ScanMode watch
            Wrapper for executing AssemblyHunter_x86.exe and AssemblyHunter_x64.exe in the same directory to watch 
            for newly created managed processes to scan for interesting assemblies.
        .LINK
            https://github.com/bohops/RogueAssemblyHunter
    #>

    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScanMode = "sweep"
    )
    

    Write-Host -ForegroundColor red @("
__________                                 _____                              ___.   .__         
\______   \ ____   ____  __ __   ____     /  _  \   ______ ______ ____   _____\_ |__ |  | ___.__.
 |       _//  _ \ / ___\|  |  \_/ __ \   /  /_\  \ /  ___//  ___// __ \ /     \| __ \|  |<   |  |
 |    |   (  <_> ) /_/  >  |  /\  ___/  /    |    \\___ \ \___ \\  ___/|  Y Y  \ \_\ \  |_\___  |
 |____|_  /\____/\___  /|____/  \___  > \____|__  /____  >____  >\___  >__|_|  /___  /____/ ____|
        \/      /_____/             \/          \/     \/     \/     \/      \/    \/     \/     
                             ___ ___               __                
                            /   |   \ __ __  _____/  |_  ___________ 
                           /    ~    \  |  \/    \   __\/ __ \_  __ \
                           \    Y    /  |  /   |  \  | \  ___/|  | \/
                            \___|_  /|____/|___|  /__|  \___  >__|   
                                  \/            \/          \/       

    ")

    Write-Host "[*] A utility for discovering 'interesting' .NET CLR modules in running processes."
    Write-Host "[*] Use this script to quickly scan all processes (default) or scan newly created processes (-ScanMode watch)"
    Write-Host "[*] For best results, run as a privileged user with high/system integrity."
    Write-Host "[*] For advanced usage, refer to the GitHub page or managed executable Help feature"
    Write-Host "[*] Note: This tool uses the CLRMD to connect to live processes, which could introduce interesting results"
    Write-Host "[*] Run at your own risk!"

    if (Test-Path .\RogueAssemblyHunter_x64.exe) {
        if ($ScanMode -eq "watch") {
            $path = $(pwd).Path + "/k RogueAssemblyHunter_x64.exe --mode=watch --nobanner --suppress"
            Start-Process cmd.exe -ArgumentList $path -NoNewWindow
        }
        else {
            .\RogueAssemblyHunter_x64.exe --mode=sweep --nobanner --suppress
        }
    }

    if (Test-Path .\RogueAssemblyHunter_x86.exe)
    {
        if ($ScanMode -eq "watch") {
            $path = $(pwd).Path + "/k RogueAssemblyHunter_x86.exe --mode=watch --nobanner --suppress"
            Start-Process cmd.exe -ArgumentList $path -NoNewWindow
        }
        else {
            .\RogueAssemblyHunter_x86.exe --mode=sweep --nobanner --suppress
        }
    }
    
    Write-Host -ForegroundColor green "`n[*] Done"
}