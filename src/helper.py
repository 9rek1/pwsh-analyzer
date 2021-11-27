import base64
import re


def decode_base64(script: str) -> str:
    """base64の文字が30字以上続く部分をデコードして返す"""
    for s in re.findall(r"[A-Za-z0-9+/=]{30,}", script):
        try:
            while len(script) % 4:
                script = script[:-1]
            script = script.replace(s, base64.b64decode(s).decode())
        except Exception:
            pass
    return script


# split("-")でバグが出うる
# (?<!`)は必要ない
def eval_format(s: str) -> str:
    result = "'"
    index_numbers = [int(i) for i in re.findall(r"\d+", s.split("-")[0])]
    tmp = "-".join(s.split("-")[1:])
    strings = [st[0][1:-1] for st in re.findall(r"((\"|\').+?(?<!`)(\2))", tmp)]
    for i in index_numbers:
        result += strings[i]
    result += "'"
    return result


# 正規表現、最後の\)が'""'の中だった場合などにバグが出うる
# re.subn()使ったほうがスマートかも
def replace_format(script: str) -> "tuple[str,bool]":
    replaced = False
    pat = r"\(\s*(\"|\')(?:\s*\{[0-9]{1,3}\}\s*)+\1\s*-[fF]\s*[\"|\'].+?[\"|\']\s*\)"
    for s in re.finditer(pat, script):
        s = s.group()
        script = script.replace(s, eval_format(s))
        replaced = True
    return script, replaced


def exists_replace(script: str) -> bool:
    """
    - Replace("`n", " ")などは悪意がない
    """
    pat = r"\.replace\(\s*[\"\']\w"
    if re.search(pat, script):
        return True
    return False


# 余裕があれば'と"の組み合わせに対応したい
# 中身にformatとかが使われているかで
# &(())とか二重になると、、、
# def extract_ampersand(script: str) -> "list[str]":
#     """
#     &または.で実行されている部分を抽出する。
#     文字列の一部だった場合などに誤抽出の可能性があるので、例外処理は必須
#     """
#     result: list[str] = []
#     pat = r"(?<![\w\)])[&\.]\s*[^\s][^\(\s]*"
#     for s in re.findall(pat, script):
#         s = re.sub(r"^[&\.]\s*", "", s)
#         result.append(s)
#     return result


def exists_ampersand(script: str) -> bool:
    pat = r"(?<![\w\)])[&\.]\s*[^\s][^\(\s]*"
    if re.search(pat, script):
        return True
    return False


# def trim_extra_spaces(script: str) -> str:
#     return script.replace("  ", " ")


def trim_backticks(script: str) -> "tuple[str, bool]":
    """
    - 無駄なバッククォートが1行に3つ以上あれば悪意あると判断
    """
    malicious = False
    pat = r"`(?=[^0abefnrtuv`])"
    lines = script.splitlines()
    for line in lines:
        if len(re.findall(pat, line)) > 2:
            malicious = True
            break
    return re.sub(pat, "", script), malicious


def is_mal_char(script: str) -> bool:
    """
    - [char](()), [char] $
    - 1行に5つ以上
    """
    pat = r"\[char\]\s*(?:$|\([^\)]*?[\($])"
    if re.search(pat, script):
        return True
    lines = script.splitlines()
    for line in lines:
        if line.count("[char") > 5:
            return True
    return False


def is_mal_one_liner(script: str) -> bool:
    """
    - 改行が異常に少ないのに、;が多用されている
    - 改行が異常に少ないのに、スクリプトは短くない(80*5以上)
    """
    if len(re.findall("(\n|\r\n)", script)) < len(script) / 80:
        if script.count(";") > len(script) / 80:
            return True
            # return script.count(";")
        if len(script) > 80 * 5:
            return True
    return False


def deobfuscate(script: str) -> "tuple[str,dict[str,bool]]":
    """スクリプトの難読化を解除する
    - base64部分をデコードする
    - すべて小文字にする
    - バッククォートを取り除く
    - フォーマット指定部分を並び替える
    - ワンライナーかどうか
    - charがあるかどうか(char + -join は別で検出している)
    """
    obf: dict[str, bool] = {}
    script = decode_base64(script)
    script = script.lower()
    script, obf["Backtick"] = trim_backticks(script)
    script, obf["Format"] = replace_format(script)
    obf["One Liner"] = is_mal_one_liner(script)
    obf["Char"] = is_mal_char(script)
    obf["Ampersand"] = exists_ampersand(script)
    obf["Replace"] = exists_replace(script)
    return script, obf
