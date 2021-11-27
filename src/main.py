# -*- coding: utf-8 -*-
import datetime
import re
import xml.etree.ElementTree as ET

from helper import deobfuscate  # ./helper
from words import black_dict  # ./words

ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"

log_sets = [
    # ("logs/winps.xml", "logs/mwpsop.xml"),
    # ("logs/cmdwinps.xml", "logs/cmdmwpsop.xml"),
    ("logs/iexwinps.xml", "logs/iexmwpsop.xml"),
]


def check_black_dict(key: str, script: str) -> bool:
    """
    black_dict[key]のワードリストのなかで、1つでも含まれるものがあるかを返す
    """
    for w_list in black_dict[key]:
        if all(w in script for w in w_list):
            return True
    return False


# def count_black_dict(key: str, script: str) -> int:
#     """
#     black_dict[key]のワードリストのなかで、スクリプトに含まれているものかいくつあるかを返す
#     """
#     return sum(all(w in script for w in w_list) for w_list in black_dict[key])


# def check_black_dict_all(script: str):
#     result: list[str] = []
#     for key in black_dict.keys():
#         for w_list in black_dict[key]:
#             if all(w in script for w in w_list):
#                 result.append(key)
#     return result


def iso_to_jst(dt: str) -> str:
    """イベントログの日時をフォーマットして返す"""
    utc = datetime.datetime.strptime(dt[:-4], "%Y-%m-%dT%H:%M:%S.%f")
    jst = utc + datetime.timedelta(hours=9)
    return jst.strftime("%Y年%-m月%-d日 %-H時%-M分%-S秒")


def get_root(file: str) -> ET.Element:
    """xmlファイルを読み込み、rootを返す"""
    with open(file, "r", encoding="utf-16") as f:
        xml = f.read()
        xml = "<eventlog>" + xml + "</eventlog>"
    return ET.fromstring(xml)


def is_mal_pwsh(text: str) -> bool:
    """悪意あるPowerShellの起動かどうかを返す
    - 悪意あるオプションが指定されているかどうかで判断
    - オプション2つ以上とかにしてもいいかもしれない
    """
    host_name = re.search(r"(?<=HostApplication\=).*?(?=\n)", text).group()
    host_name = host_name.lower()
    if ("powershell" in host_name) and check_black_dict("PowerShell", host_name):
        return True
    return False


def is_mal_iex(script: str) -> bool:
    """iexの実行が悪意あるものかどうかを返す
    - winp.xmlに対して実行する
    """
    script, obf = deobfuscate(script)
    if check_black_dict("Downloader", script):
        return True
    if check_black_dict("Obfuscation", script):
        return True
    if any(o for o in obf.values()):
        return True
    return False


def find_iex_jst(
    tgt_ppl: int, tgt_scr: str, winp_contents: "list[tuple[int, list[ET.Element], str]]"
):
    """iexを含む悪意あるスクリプトが実行された時刻を返す
    - CommandInvocation(Invoke-Expression)はパイプラインが閉じるときに記録されるため、パイプラインの開始時刻は別で取得する
    """
    for (pipeline_id, script, jst) in winp_contents:
        if tgt_ppl == pipeline_id and tgt_scr == script[0].text:
            return jst
    return ""


def warn_mal_iex(
    pipeline_id: int,
    ps: "list[ET.Element]",
    winp_contents: "list[tuple[int, list[ET.Element], str]]",
) -> None:
    """悪意あるiexの実行に対して警告を出力する"""
    if ps[2].text and "CommandInvocation(Invoke-Expression)" in ps[2].text:
        if ps[0].text and is_mal_iex(ps[0].text):
            jst = find_iex_jst(pipeline_id, ps[0].text, winp_contents)
            print("*** 警告 ***")
            print("悪意あるスクリプトがメモリ上で実行されました。")
            print(f"【日時】 {jst}")
            print(f"【スクリプト】 {ps[0].text}\n")


def warn_mal_script(script: str, jst: str) -> None:
    result = ""
    script, obf = deobfuscate(script)
    if sum(o for o in obf.values()) > 1 or (
        any(o for o in obf.values()) and check_black_dict("Obfuscation", script)
    ):
        result += "- 難読化されたスクリプトが実行されました。\n"
    if check_black_dict("ShinoBOT", script):
        result += "- ShinoBOTが実行されました。\n"
    if check_black_dict("Registry", script):
        result += "- レジストリが操作されました。\n"
        if check_black_dict("Exploit", script):
            result += "- 権限昇格が行われました。\n"
    if check_black_dict("Mimikatz", script):
        result += "- Mimikatzが実行されました。\n"
    if check_black_dict("Persistence", script):
        result += "- 新たなタスクが永続化されました。\n"
    if check_black_dict("Profile", script):
        result += "- プロファイルが変更されました。\n"
    if check_black_dict("AntiVirus", script):
        result += "- セキュリティソフトのアンインストールが実行されました\n"
    if result:
        if check_black_dict("Downloader", script):
            result += "- ダウンロードコマンドが実行されました。\n"
        print("*** 警告 ***")
        print(f"【日時】 {jst}")
        print(result)


def parse_winp(winp_root: ET.Element) -> "list[tuple[int, list[ET.Element], str]]":
    """winp.xmlから必要な情報を抽出する

    Returns:
        list[tuple[int, list[ET.Element], str]]:
            [(pipeline_id, ps, jst)]
    """
    result: list[tuple[int, list[ET.Element], str]] = []
    for event in winp_root:
        eventid = event.find(ns + "System").find(ns + "EventID").text
        ps = event.find(ns + "EventData").findall(ns + "Data")
        time = event.find(ns + "System").find(ns + "TimeCreated").attrib
        jst = iso_to_jst(time["SystemTime"])
        if eventid == "800" and ps[1].text:
            mat = re.search(r"(?<=PipelineId=)\d+", ps[1].text)
            pipeline_id = int(mat.group()) if mat else 0
            result.append((pipeline_id, ps, jst))
    return result


def analyze_winp(winp_root: ET.Element) -> None:
    winp_contents = parse_winp(winp_root)
    mal_pwsh_started = False
    for (pipeline_id, ps, jst) in winp_contents:
        if (not mal_pwsh_started) and is_mal_pwsh(ps[1].text):
            print("*** 警告 ***")
            print("悪意ある形でPowerShellが起動されました。")
            print(f"【日時】 {jst}\n")
            mal_pwsh_started = True
        warn_mal_iex(pipeline_id, ps, winp_contents)


def parse_mwp(mwp_root: ET.Element) -> "list[list[str]]":
    """mwp.xmlから必要な情報を抽出する
    - ログの都合で分割されたスクリプトは結合する

    Returns:
        list[list[str]]: [[jst, script]]
    """
    result: "list[list[str]]" = []
    for event in mwp_root:
        eventid = event.find(ns + "System").find(ns + "EventID").text
        ps = event.find(ns + "EventData").findall(ns + "Data")
        time = event.find(ns + "System").find(ns + "TimeCreated").attrib
        jst = iso_to_jst(time["SystemTime"])
        if eventid == "4104" and ps[0].text and ps[2].text:
            if ps[0].text == "1":
                result.append([jst, ps[2].text])
            else:
                result[-1][1] += ps[2].text
    return result


def analyze_mwp(mwp_root: ET.Element) -> None:
    mwp_contents = parse_mwp(mwp_root)
    for (jst, script) in mwp_contents:
        warn_mal_script(script, jst)


def main(winp_path: str, mwp_path: str) -> None:
    winp_root = get_root(winp_path)
    mwp_root = get_root(mwp_path)
    analyze_winp(winp_root)
    analyze_mwp(mwp_root)


if __name__ == "__main__":
    for (winp_path, mwp_path) in log_sets:
        main(winp_path, mwp_path)
