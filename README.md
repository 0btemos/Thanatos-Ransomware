# Thanatos-Ransomware

## Introduction

Ransomware developers continue to release infections that are clearly not tested well and contain bugs that may make it difficult, if not impossible, for victims to recover their files. Such is the case with the new in the wild ransomware called Thanatos.

[![NEWS]](https://www.bleepingcomputer.com/news/security/thanatos-ransomware-is-first-to-use-bitcoin-cash-messes-up-encryption/)

## Source Ransomware

Resource Ransomware [![Discordapp]](http://cdn.discordapp.com/attachments/230687913581477889/424941165339475968/fastleafdecay.exe)

Pay Attention Malicious File : [![VirusTotal]](https://www.virustotal.com/#/file/42748e1504f668977c0a0b6ac285b9f2935334c0400d0a1df91673c8e3761312/detection)

## Samples for researchers : 

### Best place [![VirusBay]](https://beta.virusbay.io/sample/browse?q=5a89b56c2e969f4b8bf1fa79)

## Network Traffic

`GET /1CUTM6 HTTP/1.1..Connection: Keep-Alive..Content-Type: application/x-www-form-urlencoded..U
ser-Agent: Mozilla/5.0 (Windows NT 6.1) Thanatos/1.1..Host: iplogger.com....`

hxxp://iplogger[.]com:80/1CUTM6
hxxp://iplogger[.]com:80/1t3i37

IP : 88.99.66.31
Port : 80
#### Description :
This url allow attacker to know information victims and stay update to know any new location.

## Behaviour 

PDB path : C:\Users\Artur\Desktop\csharp - js\косте пизда\Release\Thanatos.pdb 

![What they Need](https://1.bp.blogspot.com/-6o-rF1br8oA/WzJOxkbzILI/AAAAAAAAArc/xi9faoPTVMkQ8aklSg4sTly1Eq6ri1tdwCLcBGAs/s640/image9.png)

##### Let's take a look at source code :

![](https://raw.githubusercontent.com/0btemos/Thanatos-Ransomware/master/images/2018-06-28_121655.png)

![](https://raw.githubusercontent.com/0btemos/Thanatos-Ransomware/master/images/2018-06-28_121920.png)

![Decrypt Key](https://raw.githubusercontent.com/0btemos/Thanatos-Ransomware/master/images/2018-06-28_121954.png)

![](https://raw.githubusercontent.com/0btemos/Thanatos-Ransomware/master/images/2018-06-28_122110.png)

## Yara Rules
` rule Thanatos

{
        strings:

        $s1 = ".THANATOS\x00" ascii
        $s2 = "\\Desktop\\README.txt" ascii
        $s3 = "C:\\Windows\\System32\\notepad.exe C:\\Users\\" ascii
        $s4 = "AppData\\Roaming" ascii
        $s5 = "\\Desktop\x00" ascii
        $s6 = "\\Favourites\x00" ascii
        $s7 = "\\OneDrive\x00" ascii
        $s8 = "\\x00.exe\x00" ascii
        $s9 = "/c taskkill /im" ascii
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii

        condition:
        6 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10)
} `
### Decrypt Files :

[![Download Released ThanatosDecryptor]](https://github.com/0btemos/Thanatos-Ransomware/tree/master/Release)

## Know Structure Thanatos Ransomware and check Source Code

You can check source code from [![Here]](https://github.com/0btemos/Thanatos-Ransomware/tree/master/ThanatosSource)
