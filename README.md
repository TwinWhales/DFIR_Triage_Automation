# dfir-triage

시나리오 기반 아티팩트 선별과 sLLM 해석을 결합한 침해사고 트리아지 도구.

## 파이프라인

입력(자연어 또는 EDR/SIEM 알럿) -> 시나리오 정규화 -> 아티팩트 우선순위 선별
-> 결정론적 파싱 -> sLLM 해석 -> 근거 검증 -> 결과 보고

각 단계는 독립 CLI이며 파일로 입출력을 주고받습니다. 상세 계약은
`docs/pipeline-io-spec.md`를 참조하세요.

## 실행

```bash
pip install -r requirements.txt
python tools/make_case.py --case-id C-001 --evidence /mnt/evidence/WEB01
./run_pipeline.sh C-001 /mnt/evidence/WEB01
```

## 평가

```bash
python benchmark/evaluate.py --dataset benchmark/datasets/C-001-webshell
python benchmark/validator_check.py
```
