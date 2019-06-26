# Stracciatella
Powershell runspace from within C# (aka `SharpPick` technique) with AMSI and Script Block Logging disabled for your pleasure.

Nowadays, when Powershell got severly instrumented by use of techniques such as:
* AMSI
* Script Block Logging
* Transcript file
* Modules logging
* Constrained Language Mode

Advanced attackers must find ways to circumvent these efforts in order to deliver sophisticated adversarial simulation exercises. In order to help in these efforts, following project was created.

This program builds on top of bypasses for specific techniques included in:
* [Disable-Amsi.ps1](https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/red-teaming/Disable-Amsi.ps1)
* [Disable-ScriptLogging.ps1](https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/red-teaming/Disable-ScriptLogging.ps1)

Which in turn was based on following researches:
- Matt Graeber: https://github.com/mattifestation/PSReflect
- Matt Graeber: https://twitter.com/mattifestation/status/735261120487772160
- Avi Gimpel: https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/
- Adam Chester: https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
- Ryan Cobb: https://cobbr.io/ScriptBlock-Logging-Bypass.html
- Ryan Cobb: https://cobbr.io/ScriptBlock-Warning-Event-Logging-Bypass.html

The SharpPick idea, meaning to launch powershell scripts from within C# assembly by the use of Runspaces is also not new and was firstly implemented by Lee Christensen (@tifkin_) in his:
* [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)

Also, the source code borrows implementation of `CustomPSHost` from Lee.

This project inherits from above researches and great security community in order to provide close-to-be-effective Powershell environment with defenses disabled on startup.

## OpSec

* This program provides functionality to decode passed parameters on the fly, using Base64 and Xor single-byte decode (also combined)
* Before launching any command, it makes sure to disable AMSI using two approaches
* Before launching any command, it makes sure to disable Script Block logging using two approaches
* This program does not patch any system library, system native code (think amsi.dll)
* Efforts were made to not store decoded script/commands excessively long, in order to protect itself from memory-dumping techniques governed by EDRs and AVs
* The resulting binary may be considered bit too large, that's because `Costura.Fody` NuGet package is used which bundles `System.Management.Automation.dll` within resulting assembly


## Usage

There are couple of options available:

```
PS D:\> Stracciatella.exe --help

  :: Stracciatella - Powershell runspace with AMSI and Script Block Logging disabled.
  Mariusz B. / mgeeky, '19 <mb@binary-offensive.com>

Usage: stracciatella.exe [options] [script]
  script                - Path to file containing Powershell script to execute. If not options given, will enter a pseudo-shell loop.
  -v, --verbose         - Prints verbose informations
  -f, --force           - Proceed with execution even if Powershell defenses were not disabled. By default we bail out on failure.
  -c, --command         - Executes the specified commands.
                          If command and script parameters were given, executes command after running script.
  -b, --base64          - Consider input as Base64 encoded. If both options, --base64 and --xor are specified,
                          the program will peel them off accordingly: Base64Decode(XorDecode(data, XorKey))
  -x <key>, --xor <key> - Consider input as XOR encoded, where <key> is a hex 8bit value being a key
```

The program accepts command and script file path as it's input. Both are optional, if none were given - pseudo-shell will be started.
Both command and script can be further encoded using single-byte XOR or Base64 (or combination of them) for better OpSec experience.

Here are couple of examples presenting use cases:

1. *Pseudo-shell* - intiatiated when neither command nor script path options were given:

```
PS D:\> Stracciatella.exe -v

  :: Stracciatella - Powershell runspace with AMSI and Script Block Logging disabled.
  Mariusz B. / mgeeky, '19 <mb@binary-offensive.com>

[+] AMSI Disabled.
[+] Script Block Logging Disabled.
[.] Language Mode: FullLanguage

Stracciatella D:\> $PSVersionTable

Name                           Value
----                           -----
PSVersion                      5.1.18362.1
PSEdition                      Desktop
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
BuildVersion                   10.0.18362.1
CLRVersion                     4.0.30319.42000
WSManStackVersion              3.0
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1
```

2. *Base64 & XOR encoded (key = 0x31) command and path to script file*

Firstly, in order to prepare encoded statements we can use bundled `encoder.py` script, that can be used as follows:

```
PS D:\> python encoder.py -h
usage: encoder.py [options] <command|file>

positional arguments:
  command            Specifies either a command to encode or script file's
                     path

optional arguments:
  -h, --help         show this help message and exit
  -b, --base64       Consider input as Base64 encoded. If both options,
                     --base64 and --xor are specified, the program will apply
                     them accordingly: Base64Encode(XorEncode(data, XorKey))
  -x KEY, --xor KEY  Consider input as Base64 encoded. If both options,
                     --base64 and --xor are specified, the program will apply
                     them accordingly: Base64Encode(XorEncode(data, XorKey))

PS D:\> python encoder.py -b -x 0x31 "Write-Host \"It works like a charm!\" ; $ExecutionContext.SessionState.LanguageMode"
ZkNYRVQceV5CRRETeEURRl5DWkIRXVhaVBFQEVJZUENcEBMRChEVdElUUkRFWF5fcl5fRVRJRR9iVEJCWF5fYkVQRVQffVBfVkRQVlR8XlVU
```

Then we feed `encoder.py` output as input being an encoded command for Stracciatella:

```
PS D:\> Stracciatella.exe -v -b -x 0x31 -c "ZkNYRVQceV5CRRETeEURRl5DWkIRXVhaVBFQEVJZUENcEBMRChEVdElUUkRFWF5fcl5fRVRJRR9iVEJCWF5fYkVQRVQffVBfVkRQVlR8XlVU" .\Test2.ps1

  :: Stracciatella - Powershell runspace with AMSI and Script Block Logging disabled.
  Mariusz B. / mgeeky, '19 <mb@binary-offensive.com>

[.] Will load script file: '.\Test2.ps1'
[+] AMSI Disabled.
[+] Script Block Logging Disabled.
[.] Language Mode: FullLanguage

PS> & '.\Test2.ps1'
PS> Write-Host "It works like a charm!" ; $ExecutionContext.SessionState.LanguageMode
[+] Yeeey, it really worked.
It works like a charm!
FullLanguage

```

Whereas:

- `Command` was built of following commands: `Base64Encode(XorEncode("Write-Host \"It works like a charm!\" ; $ExecutionContext.SessionState.LanguageMode", 0x31))`
- `Test2.ps1` - contained: `"ZkNYRVQceV5CRRETahpsEWhUVFRIHRFYRRFDVFBdXUgRRl5DWlRVHxM="` `(Base64(XorEncode("Write-Host \"[+] Yeeey, it really worked.\"", 0x31)))`


## How do you disable AMSI & Script Block logging?

By the use of reflection, as discovered by Matt Graeber, but that program's approach was slightly modified. Instead of referring to symbols by their name, like "amsiInitFailed" - we lookup on them by going through every Assembly, Method, Type and Field available to be fetched reflectively. Then we disable AMSI by the manipulation of NonPublic & Static variables in Management.Automation assembly. The same goes for Script Block logging, whereas in this instance some of ideas were based on Ryan Cobb's (@cobbr) researches.

In fact, `Stracciatella` uses the same implementation as covered already in above mentioned `Disable-*.ps1` files of mine.

Also, **we do not attempt to patch amsi.dll**, that's a bit too noisy and may be in near future closely monitored by EDRs/HIPS/AVs. Corrupting integrity of system libraries definitely loses grounds when compared to reflective variables clobbering.


## Just show me the `Invoke-Mimikatz`, will you?

Of course, there you go:

```
PS D:\> "amsiInitFailed"
At line:1 char:1
+ "amsiInitFailed"
+ ~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent

PS D:\> . .\Invoke-Mimikatz.ps1
At line:1 char:1
+ . .\Invoke-Mimikatz.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent

PS D:\> .\Stracciatella.exe -v

  :: Stracciatella - Powershell runspace with AMSI and Script Block Logging disabled.
  Mariusz B. / mgeeky, '19 <mb@binary-offensive.com>

[-] It looks like no script path was given.
[+] AMSI Disabled.
[+] Script Block Logging Disabled.
[.] Language Mode: FullLanguage

Stracciatella D:\> . .\Invoke-Mimikatz.ps1

Stracciatella D:\> Invoke-Mimikatz -Command "coffee exit"

  .#####.   mimikatz 2.1 (x64) built on Nov 10 2016 15:31:14
 .## ^ ##.  "A La Vie, A L'Amour"
 ## / \ ##  /* * *
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
  '#####'                                     with 20 modules * * */

mimikatz(powershell) # coffee

    ( (
     ) )
  .______.
  |      |]
  \      /
   `----'

mimikatz(powershell) # exit
Bye!
```

## Known-issues, TODO

Currently, the way the Stracciatella provides runspace for powershell commands is not the most stealthiest out there. We basically create a Powershell runspace, which loads up corresponding .NET Assembly. This might be considered as a flag that stracciatella's process is somewhat shady. 

- Create fully unmanaged powershell runspace
- Implement rolling XOR with 2,3 and 4 bytes long key.
- Add Constrained Language Mode bypass
- Implement more encoding/encryption strategies, especially ones utilising environmental keying
- Disable Script Block logging first, than go after AMSI
- ~Clean essential variables ASAP, preventing easy process memory dumping and recovery of provided scripts/commands~


## Credits

- Ryan Cobb, @cobbr
- Matt Graeber, @mattifestation
- Adam Chester, @xpn
- Avi Gimpel
- Lee Christensen, @tifkin_

