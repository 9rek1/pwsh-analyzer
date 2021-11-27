black_dict: "dict[str, list[list[str]]]" = {}

black_dict["Iex"] = [["Invoke-Expression"], ["iex"]]

"""
- https://binary-pulsar.hatenablog.jp/entry/2018/11/28/090000
"""
black_dict["Downloader"] = [
    ["DownloadString"],
    ["DownloadData"],
    ["Invoke-WebRequest"],
    ["wget"],
    ["Net.WebRequest"],
    ["DownloadFile"],
    ["bitsadmin"],
    ["Start-BitsTransfer"],
    ["Sockets.TCPClient"],
]

"""
- -Joinの利用例
    https://binary-pulsar.hatenablog.jp/entry/2018/09/01/000000
- -bxorの利用例
    https://docs.microsoft.com/ja-jp/powershell/scripting/windows-powershell/wmf/whats-new/script-logging?view=powershell-7.1
"""
black_dict["Obfuscation"] = [
    ["-Join", "[char", "[int"],
    ["-bxor", "FromBase64String"],
    ["Convert", "FromBase64String"],
    ["GetString", "FromBase64String"],
    ["IO.Compression.GzipStream"],
    ["ConvertTo-SecureString", "-Key"],
]

"""
- https://qiita.com/mima_ita/items/1e6c74c7fb641852edff
"""
black_dict["Registry"] = [
    ["Remove-Item", "HKCU:"],
    ["Remove-Item", "HKCU\\"],
    ["Remove-Item", "HKLM:"],
    ["Remove-Item", "HKLM\\"],
    ["Remove-Item", "HKEY_CURRENT_USER"],
    ["Remove-Item", "HKEY_LOCAL_MACHINE"],
    ["New-ItemProperty", "-Name", "-PropertyType", "-Value"],
]


"""
- https://www.trendmicro.com/vinfo/jp/threat-encyclopedia/malware/trojanspy.win32.icedid.a
- https://www.trendmicro.com/vinfo/jp/threat-encyclopedia/malware/ransom_crypaura.mole
"""
black_dict["Profile"] = [["%All Users Profile%"], ["%User Profile%"]]

"""
- https://github.com/Sh1n0g1/Post-Compromised-Tools/blob/master/im.ps1
"""
black_dict["Mimikatz"] = [["Invoke-Mimikatz"], ["PEBytes32", "PEBytes64"]]

black_dict["ShinoBOT"] = [["SOFTWARENAME", "ShinoBOT"]]

black_dict["Persistence"] = [
    ["New-Object", "-COMObject", "Schedule.Service"],
    ["SCHTASKS"],
]

"""
- https://www.trendmicro.com/vinfo/jp/threat-encyclopedia/malware/Fileless.LEMONDUCK/
"""
black_dict["AntiVirus"] = [["AntiVirus", "Eset", "Kaspersky", "uninstall"]]

"""
レジストリとのコンボで判断
- https://github.com/Sh1n0g1/Misc-PowerShell-Stuff/blob/master/Invoke-EventVwrBypass.ps1
- https://www.mbsd.jp/blog/20171012.html
"""
black_dict["Exploit"] = [["Invoke-EventVwrBypass"], ["sdclt.exe"], ["eventvwr.exe"]]

"""
- https://www.trendmicro.com/vinfo/jp/threat-encyclopedia/malware/BKDR_FORSHARE.A/
- https://news.mynavi.jp/article/20160510-a293/
"""
black_dict["AppLocker"] = [
    ["regsvr32", "/i:http", "scrobj.dll"],
]

"""
- https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RE44vFN
"""
black_dict["PowerShell"] = [
    ["bypass"],
    ["-w", "hidden"],
    ["-ec"],
    ["-en"],
    ["-noni"],
    ["-nop"],
]

for k in black_dict.keys():
    black_dict[k] = [[word.lower() for word in words] for words in black_dict[k]]


"""iexの難読化について
- https://www.scientia-security.org/entry/2017/11/13/224035
- https://binary-pulsar.hatenablog.jp/entry/2018/09/01/000000
"""


"""参考になりそうなの
- https://github.com/JPCERTCC/ToolAnalysisResultSheet_jp

- https://github.com/pan-unit42/public_tools/tree/master/powershellprofiler
- https://unit42.paloaltonetworks.jp/practical-behavioral-profiling-of-powershell-scripts-through-static-analysis-part-1/
- https://unit42.paloaltonetworks.jp/practical-behavioral-profiling-of-powershell-scripts-through-static-analysis-part-2/
- https://unit42.paloaltonetworks.jp/practical-behavioral-profiling-of-powershell-scripts-through-static-analysis-part-3/

- https://www.paloaltonetworks.jp/company/in-the-news/2017/unit-42-pulling-back-curtains-encodedcommand-powershell-attacks
- https://www.cyberfortress.jp/2020/03/25/blog-powershell-obfuscation/
- https://github.com/gh0x0st/Invoke-PSObfuscation/blob/main/layer-0-obfuscation.md
"""
