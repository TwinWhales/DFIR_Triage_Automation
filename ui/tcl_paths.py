"""venv 안에서 Tcl/Tk 라이브러리를 못 찾는 것을 메꾼다.

윈도우 공식 배포판은 Tcl 을 ``<base_prefix>/tcl/tcl8.6`` 에 두는데, venv
안에서 ``tkinter.Tk()`` 를 만들면 ``<base_prefix>/lib/tcl8.6`` 을 찾다가
``Can't find a usable init.tcl`` 로 죽는다. 파일은 다 있고 찾는 자리만
어긋난 것이라, 증거 폴더 선택창이 500 을 냈다.

``start.bat`` 에 환경변수를 박지 않고 여기서 하는 이유가 둘이다.

1. uvicorn 을 직접 띄우는 경우에도 같아야 한다 — ``start.bat`` 이 서버
   기동에 실패했을 때 안내하는 명령이 바로 그것이다.
2. 경로에 파이썬 버전이 박히면 3.14 로 올릴 때 조용히 되돌아온다.
   ``sys.base_prefix`` 에서 유도하면 그 일이 없다.

**찾지 못하면 아무것도 하지 않는다.** 그러면 tkinter 가 내던 원래 오류가
그대로 올라온다. 짐작한 경로를 넣어 두면 진짜 이유가 가려져서, Tcl 이
정말 없는 기계와 경로만 어긋난 기계를 구별할 수 없게 된다.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


__all__ = ["ensure_tcl_library"]


#: 환경변수 이름 → (디렉터리 이름 앞부분, 그 디렉터리에 반드시 있는 파일).
#:
#: 표지 파일까지 보는 이유: ``<base_prefix>/tcl`` 에는 ``tcl8`` 처럼
#: 라이브러리가 아닌 디렉터리도 함께 있어서 이름만으로는 가려지지 않는다
#: (``tcl8`` 안에는 8.4·8.5·8.6 모듈이 들어 있고 ``init.tcl`` 은 없다).
_LIBRARIES = {
    "TCL_LIBRARY": ("tcl8.", "init.tcl"),
    "TK_LIBRARY": ("tk8.", "tk.tcl"),
}


def ensure_tcl_library() -> dict[str, str]:
    """``TCL_LIBRARY``·``TK_LIBRARY`` 가 비어 있으면 채운다.

    이미 설정돼 있으면 손대지 않는다 — 사람이 일부러 넣은 값을 덮으면
    다른 Tcl 을 쓰려는 의도를 꺾는다.

    실제로 채운 것만 ``{환경변수: 경로}`` 로 돌려준다. 아무것도 못
    찾았으면 빈 사전이다.
    """

    applied: dict[str, str] = {}

    tcl_root = Path(sys.base_prefix) / "tcl"

    if not tcl_root.is_dir():
        return applied

    for variable, (stem, marker) in _LIBRARIES.items():
        if os.environ.get(variable):
            continue

        candidates = sorted(
            (
                path
                for path in tcl_root.iterdir()
                if path.is_dir()
                and path.name.startswith(stem)
                and (path / marker).is_file()
            ),
            key=lambda path: path.name,
        )

        if not candidates:
            continue

        # 여러 버전이 함께 있으면 높은 쪽. 이름 정렬이라 8.10 이 8.9 보다
        # 앞에 오지만, Tcl 은 8.6 이후 9 로 갔으므로 이 자리에서 8.10 은
        # 나오지 않는다.
        chosen = candidates[-1]

        os.environ[variable] = str(chosen)
        applied[variable] = str(chosen)

    return applied
