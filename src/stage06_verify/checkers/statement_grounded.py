"""문장이 증거에 없는 것을 말하는가 — 근거 검증 3층위.

다른 체커들은 ``claims`` **안**을 봅니다 — 삼중항의 값이 원본과 같은가.
이 체커만 ``claims`` **밖**, 즉 자연어 문장 자체를 봅니다.

**왜 필요해졌나.** ``--mode assemble`` 에서 claims 는 파이썬이 원본에서
1:1 로 복사합니다(``stage05_interpret/assembly.py``). 그러면 ``value_match``
는 항등식입니다 — 우리가 베낀 값을 우리가 원본과 대조하는 것이라 언제나
통과합니다. 06 이 대조하는 것은 claims 뿐이었으므로, **문장이 무슨 말을
하든 아무도 보지 않았습니다.** 실물 실행(2026-09-04)에서 이렇게 통과한
문장이 있습니다.

    "컴파티텔런너.exe 가 여러 번 실행되며 …"

``CompatTelRunner.exe`` 를 한글로 음차한 이름이고, **그런 파일은 증거
어디에도 없습니다.** claims 는 타임스탬프 둘뿐이라 이름은 대조 대상이
아니었고, 보고서에는 존재하지 않는 파일명이 그대로 실립니다.

## 무엇과 대조하나 — 실측이 규칙을 정했다

처음에는 ``claims`` 만 대조 상대로 두었습니다(`work.md` 12번의 (가)가 그렇게
적혀 있습니다). **손으로 옳다고 판단해 둔 41건 중 8건이 강등됐습니다**
(``benchmark/validator/cases.json``). 걸린 것이 전부 같은 모양이었습니다.

    "shell.aspx 의 크기는 4821바이트입니다."
      claims: MFT#12345.size = 4821

``shell.aspx`` 는 **인용한 레코드 자신의 이름**입니다. ``ref`` 가 이미 그
레코드를 지목했고 ``ref_exists``·``ref_in_input`` 이 그것을 확인했는데,
문장이 그 레코드를 이름으로 부른 것을 "근거 없음"으로 세고 있었습니다.
문장의 **주어**를 환각으로 센 셈입니다.

그래서 대조 상대는 셋입니다.

1. ``claims`` 의 값
2. 인용한 ``ref`` 문자열
3. **인용한 레코드의 값 전부** — 중첩 필드와 배열 안까지

이 규칙으로 41건 중 강등은 0건입니다. 잡는 것은 **증거 어디에도 없는
표현**이고, 그것은 표기 차이가 아니라 지어낸 것입니다.

**남는 질문은 따로 있습니다** — "claims 가 문장을 다 덮는가"는 아직 아무도
보지 않습니다. 위 실측이 보여 준 것은 그것을 곧바로 강등 사유로 쓰면
정상 문장이 대량으로 미검증이 된다는 것이지, 그 질문이 닫혔다는 것이
아닙니다(``docs/limitations.md``).

## 기각이 아니라 **강등**입니다

걸린 문장은 ``unverifiable`` 로 내립니다. ``rejected`` 로 세면 환각률이
"인용한 값이 원본과 다르다"와 "문장에 증거 밖 표현이 있다" 둘을 한 수치로
섞습니다. 유형별 분포가 발표 수치라 어휘를 섞지 않습니다
(``schemas/verified.schema.json`` 의 ``reason`` 설명).

강등은 환각률의 분모에서 빠지므로 수치를 **올리는 쪽**으로 움직입니다.
그래서 이 체커는 기계적으로 확실한 것만 잡고 애매한 것은 통과시킵니다.

## 무엇을 뽑나

문장에서 **판정 가능한 것 셋**만 뽑습니다.

1. **경로** — ``C:\\…``, ``\\\\host\\share\\…``
2. **파일명** — ``이름.확장자``. 확장자에 ASCII 글자가 하나는 있어야 합니다
3. **큰 수** — 10진 4자리 이상, 그리고 ``0x`` 16진

## 안 보는 것과 그 이유

- **시각 표현** — 문장은 부분·상대 표기를 씁니다("03:22:15", "약 8분 후").
  claims 의 ISO 8601 과 곧바로 견줄 수 없어, 수를 뽑기 전에 지웁니다.
  틀린 시각은 그 시각이 claim 일 때 ``value_match`` 가 잡습니다.
- **3자리 이하의 수** — "4초 후"·"8분 뒤" 같은 **파생 수치**와 식별자를
  가를 방법이 없습니다. 312바이트 같은 작은 크기를 놓치는 대신, 정상 문장을
  강등하지 않는 쪽을 고릅니다.
- **ATT&CK 기법 번호** — ``T1059``·``T1505.003``. 문장이 인용한 값이 아니라
  분류 이름이고, 그것이 맞는지는 ``technique_supported`` 가 봅니다. 실물
  케이스 넷 전부가 여기서 걸렸습니다(2026-09-06).
- **확장자가 숫자뿐인 토큰** — ``19045.6466`` 같은 빌드 번호는 파일명이
  아닙니다.
- **일반 고유명사** — 계정명·그룹명·서비스명. 한국어 문장에서 어디까지가
  이름인지 기계가 가르지 못합니다. 여기서 시도하면 곧바로 과엄격 쪽으로
  넘어갑니다. 그래서 "Administrators 그룹에 추가되었습니다" 는 통과합니다 —
  **이 체커가 재는 범위가 아니라는 뜻이지, 검증됐다는 뜻이 아닙니다.**

## 부분 문자열을 허용합니다

``comparators`` 는 부분 문자열 일치를 금지합니다. 방향이 반대라 그렇습니다 —
거기서 묻는 것은 "주장한 값과 실제 값이 같은가"이고, 여기서 묻는 것은
"이 표현이 증거 어딘가에 있는가"입니다. ``shell.aspx`` 는 경로 값
``C:\\inetpub\\wwwroot\\upload\\shell.aspx`` **안에** 있고, 그것으로 설명
됩니다. 반대 방향(증거의 값이 문장 안에 있는가)은 보지 않습니다 — 그러면
긴 값 하나가 짧은 토큰을 전부 덮습니다.
"""

from __future__ import annotations

import re
from typing import Any

from ...common.io import normalize_path
from . import CheckContext, CheckResult, Downgrade, cited_refs

__all__ = ["check", "statement_tokens", "ungrounded", "REASON", "MAX_LISTED"]

#: 강등 사유의 머리말. 보고서와 테스트가 이 문구로 "claims 빈 문장" 쪽과
#: 구별한다.
REASON = "증거에 없는 표현"

#: 사유 문자열에 이름을 몇 개까지 적나. 나머지는 "외 N건" 으로 센다.
#: ``unverifiable`` 항목에는 ``detail`` 을 실을 자리가 없어(동결 스키마)
#: 사유 한 줄이 전부다.
MAX_LISTED = 5

#: 시각 표현. **수를 뽑기 전에 지운다** — 안 지우면 연도 ``2026`` 이
#: 식별자로 잡힌다.
_TIMESTAMP = re.compile(
    r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?:[T ]\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?Z?)?"
    r"|\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?"
)

#: 드라이브 문자 경로와 UNC 경로. 공백에서 끊는다 — ``C:\Program Files``
#: 는 ``C:/program`` 까지만 잡히지만, 그것도 증거의 경로 안에 있으면
#: 설명된다.
_PATH = re.compile(r"(?:[A-Za-z]:[\\/]|\\\\[^\s\\/]+[\\/])[^\s,;\"'()\[\]<>]*")

#: ``이름.확장자``. 경로 구분자를 넣지 않아 경로에서는 **마지막 마디만**
#: 잡힌다. 한글 음차 이름(``컴파티텔런너.exe``)을 잡으려면 앞머리에
#: 비ASCII 를 허용해야 하므로 부정 문자류로 쓴다.
_FILENAME = re.compile(r"[^\s,;:\"'()\[\]<>\\/]+\.[A-Za-z0-9]{1,8}")

#: 식별자로 볼 수 있는 수. 4자리 미만은 위 docstring 의 이유로 뺀다.
_NUMBER = re.compile(r"0[xX][0-9A-Fa-f]+|\d{4,}")

#: ATT&CK 기법 번호. **수를 뽑기 전에 지운다.**
#:
#: 점이 있는 ``T1505.003`` 은 파일명 규칙이 걸러 내지만, 점 없는 ``T1059``
#: 는 그대로 4자리 수가 된다. 실물 케이스 넷 전부에서 "…이는 T1059 기법에
#: 해당한다" 가 강등됐다(2026-09-06). 기법 번호는 문장이 **인용한 값**이
#: 아니라 분류 이름이고, 그것이 맞는지는 ``technique_supported`` 의 일이다.
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

#: 토큰 끝에 붙은 조사·문장부호를 떼는 데 쓴다. 한국어 문장은 경로와
#: 파일명에 조사가 그대로 붙는다 — ``wwwroot에``, ``shell.aspx가``.
_TRAILING = re.compile(r"[^A-Za-z0-9_$.\-)\]}]+$")


def _norm(text: str) -> str:
    """비교용 정규화. 대소문자와 경로 구분자를 지운다.

    ``normalize_path`` 를 문장에도 쓰는 것은 규칙을 하나로 두기 위해서다.
    끝의 ``/`` 를 떼는 동작까지 같아야 ``C:\\dir`` 과 ``C:/dir/`` 이 같은
    토큰이 된다.
    """
    return normalize_path(text)


def _clean(token: str) -> str:
    """토큰 끝의 조사·문장부호를 뗀다."""
    return _TRAILING.sub("", token)


def _is_filename(token: str) -> bool:
    """확장자가 파일명의 것인가.

    ``T1505.003`` 처럼 숫자뿐인 확장자를 뺀다 — 기법 번호·빌드 번호가
    파일명으로 잡히면 정상 문장이 강등된다.
    """
    stem, _, ext = token.rpartition(".")
    if not stem or not ext:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9]{1,8}", ext)) and any(c.isalpha() for c in ext)


def statement_tokens(statement: str) -> list[tuple[str, str]]:
    """문장에서 대조할 토큰을 ``(종류, 토큰)`` 으로 뽑는다.

    **순서가 있다.** 경로를 먼저 뽑아 그 구간을 지우고, 남은 자리에서
    파일명을, 다시 지우고 수를 뽑는다. 그러지 않으면 경로 하나가 경로·
    파일명·수 셋으로 세어져 사유 한 줄이 같은 것을 세 번 말한다.
    """
    tokens: list[tuple[str, str]] = []
    seen: set[str] = set()

    def take(kind: str, raw: str) -> None:
        token = _clean(raw)
        if not token:
            return
        key = f"{kind}:{_norm(token)}"
        if key in seen:
            return
        seen.add(key)
        tokens.append((kind, token))

    def blank(match: "re.Match[str]") -> str:
        return " " * len(match.group())

    # 0) 기법 번호를 먼저 지운다. 값이 아니라 분류 이름이다.
    text = _TECHNIQUE.sub(blank, statement)

    # 1) 경로. 뽑은 자리는 공백으로 지워 뒤 단계가 다시 보지 않게 한다.
    for match in _PATH.finditer(text):
        take("path", match.group())
    text = _PATH.sub(blank, text)

    # 2) 파일명.
    for match in _FILENAME.finditer(text):
        token = _clean(match.group())
        if _is_filename(token):
            take("file", token)
    text = _FILENAME.sub(blank, text)

    # 3) 수. 시각 표현을 먼저 지운다.
    text = _TIMESTAMP.sub(blank, text)
    for match in _NUMBER.finditer(text):
        take("number", match.group())

    return tokens


def _as_int(token: str) -> "int | None":
    try:
        return int(token, 16) if token[:2].lower() == "0x" else int(token)
    except ValueError:
        return None


def _scalars(node: Any, out: list[Any]) -> None:
    """중첩 구조 안의 스칼라 값을 모두 꺼낸다.

    JSON 문자열로 만들어 훑지 않는 것은 이스케이프 때문이다 — 경로의
    ``\\`` 가 ``\\\\`` 로 바뀌어 정규화 뒤에도 토큰과 어긋난다.
    """
    if isinstance(node, dict):
        for value in node.values():
            _scalars(value, out)
    elif isinstance(node, list):
        for item in node:
            _scalars(item, out)
    elif node is not None:
        out.append(node)


def _evidence(finding: dict[str, Any], records: dict[str, dict[str, Any]]) -> "tuple[str, set[int]]":
    """이 소견이 기댈 수 있는 것 전부 — 정규화한 본문과 정수 집합.

    셋을 합친다. ``claims`` 의 값, 인용한 ``ref`` 문자열, 그리고 **인용한
    레코드의 값 전부**. 셋째가 없으면 문장의 주어가 환각으로 잡힌다 —
    모듈 첫머리의 실측 참조.

    파싱 결과에 없는 ``ref`` 는 건너뛴다. 그 판정은 ``ref_exists`` 의
    것이고, 여기서 또 걸면 같은 잘못이 두 유형으로 집계된다.
    """
    parts: list[Any] = list(cited_refs(finding))

    for claim in finding.get("claims", []):
        parts.append(claim.get("value"))

    for ref in cited_refs(finding):
        record = records.get(ref)
        if record is not None:
            _scalars(record, parts)

    numbers: set[int] = set()
    text: list[str] = []
    for value in parts:
        if value is None:
            continue
        text.append(str(value))
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            numbers.add(value)
        elif isinstance(value, float) and value.is_integer():
            numbers.add(int(value))
        elif isinstance(value, str):
            parsed = _as_int(value.strip())
            if parsed is not None:
                numbers.add(parsed)

    return _norm(" | ".join(text)), numbers


def ungrounded(finding: dict[str, Any], records: "dict[str, dict[str, Any]] | None" = None) -> list[str]:
    """증거가 설명하지 않는 토큰. 문장에 나온 순서 그대로."""
    haystack, numbers = _evidence(finding, records or {})
    missing: list[str] = []

    for kind, token in statement_tokens(finding.get("statement", "")):
        if kind == "number":
            value = _as_int(token)
            if value is not None and value in numbers:
                continue
        if _norm(token) in haystack:
            continue
        missing.append(token)

    return missing


def check(finding: dict[str, Any], ctx: CheckContext) -> CheckResult:
    """문장이 증거 밖의 것을 말하면 ``unverifiable`` 로 내린다.

    ``claims`` 가 비어 있으면 아무것도 하지 않는다 — 그 소견은 이미
    ``unverifiable`` 이고(종합 판단 문장), 여기서 또 사유를 덮어쓰면
    "claims 가 없다"와 "증거에 없는 표현이 있다"가 한 어휘로 뭉개진다.

    ``checks`` 도 올리지 않는다. 그 수는 **claims 대조 횟수**여야 하고
    이것은 문장 단위의 판정이다(``technique_supported`` 와 같은 이유).
    """
    if not finding.get("claims"):
        return CheckResult()

    missing = ungrounded(finding, ctx.records)
    if not missing:
        return CheckResult()

    listed = ", ".join(missing[:MAX_LISTED])
    if len(missing) > MAX_LISTED:
        listed += f" 외 {len(missing) - MAX_LISTED}건"
    return CheckResult(downgrade=Downgrade(reason=f"{REASON}: {listed}"))
