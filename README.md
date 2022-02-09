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

# Rogue Assembly Hunter

Rogue Assembly Hunter is a utility for discovering 'interesting' .NET CLR modules in running processes.

* Author: @bohops
* License: MIT
* Project: https://github.com/bohops/RogueAssemblyHunter

## Background

.NET is a very powerful and capable development platform and runtime framework for building and running .NET managed applications. Over the last several 
years, .NET has been adopted by Red Teams (and likes thereof) for instrumenting tradecraft to support offensive operations. In particular, the shift from
offensive PowerShell to .NET was a logical leap (for many) due to the increased optics and opportunistic visibility present in PowerShell v5+. As such, 
.NET offensive tooling and tradecraft has been successfully used to evade host-based defensive capabilities, bypass application control, and to 
build/stage/deliver/execute malicious code (similar to PowerShell).

From a prevention perspective, Microsoft is doing more to combat .NET instrumented threats and to minimize the overall .NET attack surface. For example, 
Microsoft has added [AMSI](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) inspection capabilities in .NET Framework 4.8, and [WDAC](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)/[WLDP](https://docs.microsoft.com/en-us/windows/win32/devnotes/windows-lockdown-policy) mechanisms are quite effective. From a detection/response perspective, further 
visibility and introspection into the .NET ecosystem is always advantageous for discovering new ways to combat .NET-focused threats.

In 2017, Joe Desimone ([@dez_](https://mobile.twitter.com/dez_)) wrote a fantastic article called [Hunting For In-Memory .NET Attacks](https://www.elastic.co/blog/hunting-memory-net-attacks). Still relevant today, the article outlines modern .NET attack
vectors as well as on-demand and event-based techniques for detection. Accompanying the article, Joe released a tool ([Get-ClrReflection](https://gist.github.com/dezhub/2875fa6dc78083cedeab10abc551cb58)) to 
proactively detect (and retrieve) in-memory .NET CLR modules that lack a proper disk reference. Inspired by Joe's work and taking advantage of the 
introspection capabilities of the CLRMD runtime diagnostics library (+ subsequent data access capabilities of mscordacwks.dll), 
Rogue Assembly Hunter was created to:

* Inspect (all) running .NET ('managed') processes for interesting CLR modules (e.g. module(s) that form an 'assembly')
* Inspect a single .NET ('managed') process (by PID) for interesting CLR modules
* Watch for newly spawned processes and attempt to inspect for interesting CLR modules
* Support several 'hunt' capabilities to discover in-memory loaded modules, signature status of modules (if loaded from disk), modules loaded from interesting
  directories, and imposter modules (e.g. fake file references).
* Support CLR module export functionality (a quick port from Get-ClrReflection)
* Inspire more interesting tooling and tradecraft

## Major Requirements & Dependencies

*  Run under a privileged user/process context
* .NET Framework 4.6.1+
* [.NET CLRMD](https://github.com/microsoft/clrmd) - Microsoft.Diagnostics.Runtime Introspection Library (NuGet Package)
* [ILMerge]([https://github.com/dotnet/ILMerge) - Static Linker (NuGet Package)
* ...and supporting NuGet packages in Visual Studio.

## Notes, Tips, & Caveats

* Run as a privileged user with high/system integrity.
* 'Hunts' are experimental and not guaranteed to provide complete/correct results. Beware of false positives (e.g. signed modules) and validate accordingly.
* RogueAssemblyHunter uses the CLRMD to connect to live processes, which could introduce interesting results.
* Due to the scanning nature of RogueAssemblyHunter, there is a possibility of race conditions and missed results. Consider tuning with the --checks and --sleep switches to help
  (especially in 'watch' mode). In some cases, it may be difficult to 'catch' a particular assembly load due to speed of execution (such as execute-assembly and sacrificial processes).
* Architecture ('bitness') and .NET versions matter (e.g. 4+) for interacting with remote processes with the .NET CLRMD libraries.
  - For maximum inspection/coverage, build and run this program for x86 and x64 use cases.
  - Process sweep mode will attempt to connect to all running processes regardless of 'bitness'. It will otherwise fail accordingly for architecture mismatches.
* Tested on Windows 10 Pro 2H1H and Windows Server 2016 Standard 1607. It may run on other versions with the relevant .NET Framework.
* Visual Studio project source with NuGet packages, PowerShell script, and release binaries are included with this project.
* Notice.md includes project disclaimers and license information.
* **Run at your own risk (and don't mind my horrible code ;) )!**

## Usage

```
[*] Parameters:
    
    --mode=<.>   : Required | Select analysis mode. Options include sweep, process, and watch.

    --hunt=<.>   : Optional | Select the hunt scan type to find interesting CLR modules. Specify all (default), memory-only, unusual-dir,
                   sig-status, imposter-file, or list.

    --export=<.> : Optional, Experimental | Specify a file path to export loaded CLR modules for in-memory hunt scans and imposter-file hunt scans 
                   (e.g. --hunt=memory-only/imposter-file/all).

    --pid=<.>    : Optional | Specify a targeted process by PID. Must be used with --mode=process parameter/value.

    --checks=<.> : Optional | Specify a value for scan cycles. This may help reduce race condition misses during scans but could also repeat result output.
                   Default value is 1.

    --sleep=<.>  : Optional | Specify a value for sleep seconds. This may help reduce race condition misses during scans by delaying the check cycle.
                   Default value is 0 seconds.

    --debug      : Optional | Display exception information (e.g. process connect errors).

    --nobanner   : Optional | Suppress the display banner. Useful for executing with the PowerShell script or for use cases that leverage automation.

    --suppress   : Optional | Do not scan the RogueAssemblyHunter process during --mode=sweep or --mode=watch.

    --help       : Optional | Show this help. This will override any other cmdline parameters and exit the application. *This is the default without parameters.


[*] Modes (--mode=)

    - sweep   : Scan/iterate through all processes (Note: Only processes of like architecture/'bitness' will be successfully scanned. Compile to run for x86/x64/etc.).

    - process : Scan a single process. Use with --pid=<PID>.
    
    - watch   : Scan new processes when created. Adjust scan attributes with --checks and --sleep. (Note: This is experimental. Race conditions are likely.)


[*] Hunts (--hunt=)

    - all           : Default value. Analyze with all hunt options (Except 'list').

    - memory-only   : Memory hunt. Analyze CLR modules that are not backed by disk.

    - unusual-dir   : Unusual directory hunt. Analyze CLR modules loaded outside of 'normal' directories.
                      Edit '_huntUnusualDirectoryFilter' to customize.

    - sig-status    : File signature hunt. Analyze CLR modules with anomalous signature status (e.g. unsigned). Note: This is experimental. False positives are possible.
                      Edit '_huntSigExclusionsFilter'  to customize.

    - imposter-file : Unexpected CLR module hunt. Analyze CLR module with suspicious disk file backing. Experimental.
    
    - list          : Iterate through all CLR modules and list accordingly.


[*] Example Usage
    
    - Example 1 : Scan processes and run through all hunts for accessible 64-bit processes (except 'list') -
                  RogueAssemblyHunter_x64.exe --mode=sweep
    
    - Example 2 : Scan processes, list all CLR modules in accessible 32-bit managed processes, and show error information -
                  RogueAssemblyHunter_x86.exe --mode=sweep --hunt=list --debug

    - Example 3 : Watch for new processes, scan all CLR modules (if managed and 64-bit), do not scan the RogueAssemblyHunter process, and do 2 checks with a 3 second delay between - 
                  RogueAssemblyHunter_x64.exe --mode=watch --suppress --checks=2 --sleep=3

    - Example 4 : Scan single process by PID, list in-memory only CLR module findings, and export CLR modules to specified path -
                  RogueAssemblyHunter_x86.exe --mode=process --pid=4650 --hunt=memory-only --export=c:\evilassemblies\
    
    - Example 5 : Scan processes, list in-memory only CLR module findings for accessible 64-bit processes, do no scan RogueAssemblyHunter process, and do not show title banner -
                  RogueAssemblyHunter_x64.exe --mode=sweep --hunt=memory-only --suppress --nobanner

```

## Release Files: Invoke-RogueAssemblyHunter & Compiled Binaries

For convinience, a PowerShell script along with two compiled binaries (RogueAssemblyHunter_x64.exe and RogueAssemblyHunter_x86.exe) have been included
in the \Release folder. Feel free to modify to fit your use cases (e.g. deployment, embedding, checks, sleep, etc.).

**Example Usage:**

Run Invoke-RogueAssemblyHunter in sweep mode and check for all hunt options
```
cd c:\path\to\RogueAssemblyHunter
import-module .\Invoke-RogueAssemblyHunter.ps1
Invoke-RogueAssemblyHunter
```

Run Invoke-RogueAssemblyHunter in watch mode and check for all hunt options
```
cd c:\path\to\RogueAssemblyHunter
import-module .\Invoke-RogueAssemblyHunter.ps1
Invoke-RogueAssemblyHunter -ScanMode watch
```

**SHA256 Hashes:**

````
e804711a8b6469f1b13b388de47dfa6dde1c85279d365db7b6e19e1644990fa6  Invoke-RogueAssemblyHunter.ps1
cc985d918e566671aa209142abc55bd798ca6c1a18730b785ac8c18d489736c3  RogueAssemblyHunter_x64.exe
ae3aead43871e263cd8465d5356c4daaae0635714321f872c931ec825008287a  RogueAssemblyHunter_x86.exe
````

## Roadmap

* Managed dump (.dmp) file analysis
* Improve sig-status check(s)
* Output improvements (e.g. json)
* Stability and bug fixes

## Credits, Inspiration, & Resources

* [Hunting For In-Memory .NET Attacks](https://www.elastic.co/blog/hunting-memory-net-attacks) | by Joe Desimone ([@dez_](https://mobile.twitter.com/dez_))
* [Get-ClrReflection](https://gist.github.com/dezhub/2875fa6dc78083cedeab10abc551cb58) | by Joe Desimone ([@dez_](https://mobile.twitter.com/dez_))
* [Get-InjectedThread](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2) | by Jared Atkinson ([@jaredcatkinson](https://mobile.twitter.com/jaredcatkinson))
* [pe-sieve](https://github.com/hasherezade/pe-sieve) | by hasherezade ([@hasherezade](https://mobile.twitter.com/hasherezade))
* [CLR MD — Analyzing Live Process](https://harshaprojects.wordpress.com/2015/12/29/clr-md-analyzing-live-process/) | by Harsha
* [How to enumerate Modules in each App Domain using ClrMD](https://sukesh.me/2020/06/12/how-to-enumerate-modules-in-each-app-domain-using-clrmd/) | by Sukesh Ashok Kumar
* [WMIProcessWatcher](https://github.com/malcomvetter/WMIProcessWatcher/) | by Tim MalcomVetter ([@malcomvetter](https://twitter.com/malcomvetter))
