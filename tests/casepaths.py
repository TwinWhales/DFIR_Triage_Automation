"""C-001 케이스 파일의 위치. **어느 파일이 재생성 가능한지가 경로로 갈린다.**

예전에는 ``benchmark/datasets/C-001-webshell/mock/`` 한 폴더에 전부 있었고,
어느 것이 손으로 쓴 입력이고 어느 것이 코드의 기대 출력인지는 데이터셋
README의 표를 봐야 알 수 있었다. 그 표가 있다는 것 자체가 신호였다 —
역할이 다른 파일들이 한 폴더에 있으면 갱신해도 되는지를 매번 물어야 한다.

실제로 위험한 조합이 있었다. ``03_selection.json``은 ``select.py``의 기대
출력이면서 동시에 04단계 테스트의 **입력**이다. 매핑을 고쳐 골든을 갱신하면
04가 무엇을 받는지도 같이 바뀌는데, 그것이 diff 에 드러나지 않는다.

이제 둘로 갈렸다.

``benchmark/fixtures/``
    코드가 만들 수 없는 것. 사람이 쓴 입력과 모델 응답 대역이다.
    **재생성하지 않는다.** 고칠 일이 있으면 손으로 고치고 왜 고쳤는지 남긴다.

``benchmark/golden/``
    코드가 만든 것을 굳힌 것. 기대 출력이므로 **의도적으로 재생성한다**.
    diff 가 곧 회귀다.

``case_file`` 은 케이스 디렉터리 하나를 흉내 내는 자리(01~07을 한 폴더에
복사해 두고 단계를 돌리는 테스트)를 위한 것이다. 그런 곳은 두 종류를 함께
다루는 것이 정상이므로, 분류를 호출부마다 되풀이하지 않고 여기 한 번만 적는다.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["CASE", "DATASET", "FIXTURES", "GOLDEN", "GOLDEN_FILES", "case_file"]

REPO_ROOT = Path(__file__).resolve().parents[1]

#: 이 픽스처들이 대변하는 케이스.
CASE = "C-001-webshell"

#: 측정 대상 — 입력과 정답. 파이프라인 산출물은 여기 없다.
DATASET = REPO_ROOT / "benchmark/datasets" / CASE

#: 손으로 쓴 것. 재생성 금지.
FIXTURES = REPO_ROOT / "benchmark/fixtures" / CASE

#: 코드가 만든 것을 굳힌 것. 재생성 대상.
GOLDEN = REPO_ROOT / "benchmark/golden" / CASE

#: ``golden/`` 에 사는 파일 이름. **이 집합이 분류의 유일한 출처다.**
#: 여기 없는 이름은 픽스처로 친다 — 새 파일이 조용히 골든이 되지 않게
#: 하려는 것이고, 재생성 도구도 이 목록만 건드려야 한다.
GOLDEN_FILES = frozenset(
    {
        "03_selection.json",
        "06_verified.json",
        "06_verified.bad.json",
        "07_report.md",
    }
)


def case_file(name: str) -> Path:
    """케이스 파일 하나의 경로. 픽스처인지 골든인지는 이름이 정한다."""
    return (GOLDEN if name in GOLDEN_FILES else FIXTURES) / name
