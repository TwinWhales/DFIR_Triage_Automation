"""``_flags.yaml`` 의 어휘로 ``parsed_record`` 스키마의 enum 을 맞춘다.

flags 어휘는 두 곳에 나타나야 합니다. 04단계가 붙일 때 쓰는 목록과,
스키마가 검증할 때 쓰는 enum 입니다. 둘이 갈라지면 파서가 만든 flag를
스키마가 거부하거나, 반대로 오타 flag가 통과합니다.

예전에는 사람이 두 파일을 같이 고치고 테스트가 감시했습니다. 지금은
``mappings/_flags.yaml`` 이 원본이고 이 스크립트가 스키마를 따라오게
합니다. **손으로 고치는 파일은 YAML 하나입니다.**

``schemas/`` 는 동결 대상이라 스키마 파일의 나머지 서식은 건드리지
않습니다. enum 배열 하나만 문자열 치환으로 바꿉니다. ``json.dump`` 로
다시 쓰면 손으로 맞춰 둔 줄바꿈이 전부 흐트러져 동결된 파일에 거대한
diff 가 생깁니다.

사용법::

    # 스키마를 YAML에 맞춘다
    .venv/Scripts/python.exe tools/sync_flag_enum.py

    # 어긋났는지 보기만 한다 (어긋나면 종료 코드 1)
    .venv/Scripts/python.exe tools/sync_flag_enum.py --check
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
FLAGS_YAML = REPO_ROOT / "mappings/_flags.yaml"
SCHEMA = REPO_ROOT / "schemas/parsed_record.schema.json"

#: ``"flags"`` 속성 안의 enum 배열만 집는다. 다른 속성에도 enum 이
#: 생길 수 있으므로 ``"flags"`` 를 앵커로 둔다.
ENUM_BLOCK = re.compile(r'(?s)("flags"\s*:\s*\{.*?"enum"\s*:\s*\[)(.*?)(\s*\])')


def declared_flags(path: Path = FLAGS_YAML) -> list[str]:
    """``_flags.yaml`` 이 정의한 어휘를 **적힌 순서대로** 돌려준다.

    순서가 곧 레코드의 ``flags`` 배열 순서라, enum 도 같은 순서로 두면
    두 파일을 나란히 놓고 읽을 수 있습니다.
    """
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    flags = data.get("flags")
    if not isinstance(flags, dict) or not flags:
        raise SystemExit(f"{path}: flags 가 비어 있음")
    return list(flags)


def schema_flags(text: str) -> list[str]:
    """스키마 텍스트에 현재 적힌 enum."""
    match = ENUM_BLOCK.search(text)
    if match is None:
        raise SystemExit(f"{SCHEMA}: flags 의 enum 배열을 찾지 못했다")
    return json.loads("[" + match.group(2) + "]")


def rewritten(text: str, flags: list[str]) -> str:
    """enum 배열만 갈아 끼운 스키마 텍스트."""
    match = ENUM_BLOCK.search(text)
    if match is None:
        raise SystemExit(f"{SCHEMA}: flags 의 enum 배열을 찾지 못했다")

    # 기존 배열의 들여쓰기를 그대로 따른다. 동결 파일에 서식 diff 를
    # 남기지 않는 것이 이 스크립트의 절반이다.
    indent = re.search(r"\n(\s*)", match.group(2))
    pad = indent.group(1) if indent else "          "
    body = "\n" + ",\n".join(f'{pad}{json.dumps(f, ensure_ascii=False)}' for f in flags)
    closing = re.search(r"\n(\s*)\]$", match.group(0))
    tail = "\n" + (closing.group(1) if closing else pad[:-2]) + "]"

    return text[: match.start()] + match.group(1) + body + tail + text[match.end() :]


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python tools/sync_flag_enum.py",
        description="mappings/_flags.yaml 의 어휘로 parsed_record 스키마의 enum 을 맞춘다.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="고치지 않고 어긋났는지만 본다. 어긋나면 종료 코드 1",
    )
    args = parser.parse_args(argv)

    flags = declared_flags()
    text = SCHEMA.read_text(encoding="utf-8")
    current = schema_flags(text)

    if current == flags:
        print(f"이미 일치한다 — {len(flags)}개: {', '.join(flags)}")
        return 0

    added = [f for f in flags if f not in current]
    removed = [f for f in current if f not in flags]
    for name in added:
        print(f"  + {name}")
    for name in removed:
        print(f"  - {name}")
    if not added and not removed:
        print("  순서만 다르다")

    if args.check:
        print(
            f"\n{SCHEMA.relative_to(REPO_ROOT)} 가 어휘와 어긋났다. "
            "tools/sync_flag_enum.py 를 돌린다.",
            file=sys.stderr,
        )
        return 1

    SCHEMA.write_text(rewritten(text, flags), encoding="utf-8")
    print(f"\n{SCHEMA.relative_to(REPO_ROOT)} 갱신 — {len(flags)}개")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
