"""dfir-triage 파이프라인.

각 단계는 ``python -m src.stageNN_xxx.yyy`` 로 실행되는 독립 CLI다.
단계 간 통신은 파일로만 하며, 유일한 공용 코드는 ``src.common``이다.
"""
