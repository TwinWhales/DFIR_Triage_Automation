document.addEventListener("DOMContentLoaded", () => {
    const caseIdInput = document.getElementById("case-id");
    const modelSelect = document.getElementById("model");
    const incidentInput = document.getElementById("incident");
    const evidenceInput = document.getElementById("evidence");

    const browseButton = document.getElementById("browse-button");
    const browseImageButton = document.getElementById("browse-image-button");
    const startButton = document.getElementById("start-button");
    const loadCaseButton = document.getElementById("load-case-button");
    const clearButton = document.getElementById("clear-log");

    const statusBadge = document.getElementById("analysis-status");
    const log = document.getElementById("live-log");

    const volumePanel = document.getElementById("volume-panel");
    const volumeList = document.getElementById("volume-list");
    const continueVolumeButton =
        document.getElementById("continue-volume-button");

    // Errors UI
    const errorCount =
        document.getElementById("error-count");

    const errorRetryCount =
        document.getElementById("error-retry-count");

    const errorSkipCount =
        document.getElementById("error-skip-count");

    const errorAbortCount =
        document.getElementById("error-abort-count");

    const errorList =
        document.getElementById("error-list");

    // Final Report UI
    const reportFilename =
        document.getElementById("report-filename");

    const reportContainer =
        document.getElementById("report-container");

    let pollTimer = null;
    let selectedVolume = null;


    // ------------------------------------------------------------
    // Evidence Folder 선택
    // ------------------------------------------------------------

    browseButton.addEventListener(
        "click",
        async () => {
            browseButton.disabled = true;
            browseButton.textContent = "여는 중...";

            try {
                const response =
                    await fetch(
                        "/api/evidence/browse"
                    );

                const data =
                    await response.json();

                if (!response.ok) {
                    throw new Error(
                        data.detail ||
                        "증거 폴더 선택에 실패했습니다."
                    );
                }

                if (
                    data.selected &&
                    data.path
                ) {
                    evidenceInput.value =
                        data.path;
                }

            } catch (error) {
                alert(
                    error.message
                );

            } finally {
                browseButton.disabled = false;
                browseButton.textContent =
                    "폴더 선택";
            }
        }
    );


    // ------------------------------------------------------------
    // Disk Image 선택
    // ------------------------------------------------------------

    browseImageButton.addEventListener(
        "click",
        async () => {
            browseImageButton.disabled = true;
            browseImageButton.textContent =
                "여는 중...";

            try {
                const response =
                    await fetch(
                        "/api/evidence/browse-image"
                    );

                const data =
                    await response.json();

                if (!response.ok) {
                    throw new Error(
                        data.detail ||
                        "디스크 이미지 선택에 실패했습니다."
                    );
                }

                if (
                    data.selected &&
                    data.path
                ) {
                    evidenceInput.value =
                        data.path;
                }

            } catch (error) {
                alert(
                    error.message
                );

            } finally {
                browseImageButton.disabled = false;

                browseImageButton.textContent =
                    "디스크 이미지";
            }
        }
    );


    // ------------------------------------------------------------
    // Live Log 초기화
    // ------------------------------------------------------------

    clearButton.addEventListener(
        "click",
        () => {
            log.textContent = "";
        }
    );


    // ------------------------------------------------------------
    // 기존 Case 불러오기
    // ------------------------------------------------------------

    loadCaseButton.addEventListener(
        "click",
        async () => {
            const caseId =
                caseIdInput.value.trim();

            if (!caseId) {
                alert(
                    "불러올 Case ID를 입력해주세요."
                );

                caseIdInput.focus();
                return;
            }

            stopPolling();

            loadCaseButton.disabled = true;
            loadCaseButton.textContent =
                "불러오는 중...";

            try {
                const loaded =
                    await loadCase(
                        caseId
                    );

                if (!loaded) {
                    return;
                }

                statusBadge.textContent =
                    "불러옴";

                appendLog(
                    `[8vidence] 기존 Case 불러오기 완료: ${caseId}`
                );

                document
                    .getElementById(
                        "errors-panel"
                    )
                    .scrollIntoView({
                        behavior: "smooth",
                        block: "start",
                    });

            } finally {
                loadCaseButton.disabled = false;

                loadCaseButton.textContent =
                    "기존 Case 불러오기";
            }
        }
    );


    // ------------------------------------------------------------
    // 기존 Case 결과 조회
    // Errors + Final Report
    // ------------------------------------------------------------

    async function loadCase(
        caseId
    ) {
        try {
            const encodedCaseId =
                encodeURIComponent(
                    caseId
                );

            const [
                errorsResponse,
                reportResponse,
            ] = await Promise.all([
                fetch(
                    `/api/results/${encodedCaseId}/errors`
                ),

                fetch(
                    `/api/results/${encodedCaseId}/report`
                ),
            ]);

            const errorsData =
                await errorsResponse.json();

            const reportData =
                await reportResponse.json();

            if (!errorsResponse.ok) {
                throw new Error(
                    errorsData.detail ||
                    "Case 오류 기록을 불러오지 못했습니다."
                );
            }

            if (!reportResponse.ok) {
                throw new Error(
                    reportData.detail ||
                    "Case 보고서를 불러오지 못했습니다."
                );
            }

            renderErrors(
                errorsData
            );

            renderReport(
                reportData
            );

            return true;

        } catch (error) {
            statusBadge.textContent =
                "준비";

            appendLog(
                `[UI 오류] ${error.message}`
            );

            alert(
                error.message
            );

            return false;
        }
    }


    // ------------------------------------------------------------
    // 최초 분석 시작
    // ------------------------------------------------------------

    startButton.addEventListener(
        "click",
        async () => {
            const caseId =
                caseIdInput.value.trim();

            const evidence =
                evidenceInput.value.trim();

            const raw =
                incidentInput.value.trim();

            const model =
                modelSelect.value;

            if (!caseId) {
                alert(
                    "Case ID를 입력해주세요."
                );

                caseIdInput.focus();
                return;
            }

            if (!raw) {
                alert(
                    "사고 내용을 입력해주세요."
                );

                incidentInput.focus();
                return;
            }

            if (!evidence) {
                alert(
                    "증거 경로를 선택해주세요."
                );

                evidenceInput.focus();
                return;
            }

            stopPolling();

            selectedVolume = null;

            hideVolumeSelection();
            resetStages();
            resetErrors();
            resetReport();

            startButton.disabled = true;

            statusBadge.textContent =
                "시작 중";

            appendLog(
                "[8vidence] 분석을 시작합니다..."
            );

            await startAnalysis({
                caseId: caseId,
                evidence: evidence,
                raw: raw,
                model: model,
                volume: null,
                force: false,
            });
        }
    );


    // ------------------------------------------------------------
    // Volume 선택 후 분석 재실행
    // ------------------------------------------------------------

    continueVolumeButton.addEventListener(
        "click",
        async () => {
            if (
                selectedVolume === null
            ) {
                alert(
                    "분석할 NTFS 볼륨을 선택해주세요."
                );

                return;
            }

            const caseId =
                caseIdInput.value.trim();

            const evidence =
                evidenceInput.value.trim();

            const raw =
                incidentInput.value.trim();

            const model =
                modelSelect.value;

            stopPolling();

            continueVolumeButton.disabled =
                true;

            startButton.disabled =
                true;

            statusBadge.textContent =
                "재시작 중";

            appendLog(
                `[8vidence] NTFS 볼륨 ${selectedVolume} 선택`
            );

            appendLog(
                "[8vidence] 기존 임시 Case를 정리하고 선택한 볼륨으로 분석을 다시 시작합니다."
            );

            await startAnalysis({
                caseId: caseId,
                evidence: evidence,
                raw: raw,
                model: model,
                volume: selectedVolume,
                force: true,
            });
        }
    );


    // ------------------------------------------------------------
    // 분석 시작 API 호출
    // ------------------------------------------------------------

    async function startAnalysis({
        caseId,
        evidence,
        raw,
        model,
        volume,
        force,
    }) {
        try {
            const response =
                await fetch(
                    "/api/analysis/start",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json",
                        },

                        body:
                            JSON.stringify({
                                case_id:
                                    caseId,

                                evidence:
                                    evidence,

                                raw:
                                    raw,

                                model:
                                    model,

                                volume:
                                    volume,

                                force:
                                    force,
                            }),
                    }
                );

            const data =
                await response.json();

            if (!response.ok) {
                throw new Error(
                    data.detail ||
                    "분석 시작에 실패했습니다."
                );
            }

            statusBadge.textContent =
                "분석 중";

            if (
                volume !== null
            ) {
                volumePanel.hidden =
                    true;
            }

            startPolling(
                caseId
            );

        } catch (error) {
            statusBadge.textContent =
                "실패";

            startButton.disabled =
                false;

            if (
                selectedVolume !== null
            ) {
                continueVolumeButton.disabled =
                    false;
            }

            appendLog(
                `[UI 오류] ${error.message}`
            );

            alert(
                error.message
            );
        }
    }


    // ------------------------------------------------------------
    // 분석 상태 Polling
    // ------------------------------------------------------------

    function startPolling(
        caseId
    ) {
        stopPolling();

        pollAnalysis(
            caseId
        );

        pollTimer =
            setInterval(
                () => {
                    pollAnalysis(
                        caseId
                    );
                },
                1000
            );
    }


    async function pollAnalysis(
        caseId
    ) {
        try {
            const response =
                await fetch(
                    `/api/analysis/${encodeURIComponent(caseId)}/status`
                );

            const data =
                await response.json();

            if (!response.ok) {
                throw new Error(
                    data.detail ||
                    "분석 상태 조회에 실패했습니다."
                );
            }

            updateStages(
                data.stages
            );

            updateLogs(
                data.logs
            );

            statusBadge.textContent =
                formatAnalysisStatus(
                    data.status
                );

            await updateErrors(
                caseId
            );


            // ----------------------------------------------------
            // 다중 NTFS Volume 발견
            // ----------------------------------------------------

            if (
                data.status ===
                "volume_required"
            ) {
                stopPolling();

                startButton.disabled =
                    false;

                showVolumeSelection(
                    data.volume_candidates ||
                    []
                );

                await updateErrors(
                    caseId
                );

                return;
            }


            // ----------------------------------------------------
            // 정상 완료
            // ----------------------------------------------------

            if (
                data.status ===
                "completed"
            ) {
                stopPolling();

                startButton.disabled =
                    false;

                continueVolumeButton.disabled =
                    true;

                hideVolumeSelection();

                await updateErrors(
                    caseId
                );

                await updateReport(
                    caseId
                );

                return;
            }


            // ----------------------------------------------------
            // 일반 실패
            // ----------------------------------------------------

            if (
                data.status ===
                "failed"
            ) {
                stopPolling();

                startButton.disabled =
                    false;

                if (
                    selectedVolume !== null
                ) {
                    continueVolumeButton.disabled =
                        false;
                }

                await updateErrors(
                    caseId
                );

                return;
            }

        } catch (error) {
            stopPolling();

            statusBadge.textContent =
                "실패";

            startButton.disabled =
                false;

            if (
                selectedVolume !== null
            ) {
                continueVolumeButton.disabled =
                    false;
            }

            appendLog(
                `[UI 오류] ${error.message}`
            );
        }
    }


    // ------------------------------------------------------------
    // Polling 중지
    // ------------------------------------------------------------

    function stopPolling() {
        if (
            pollTimer !== null
        ) {
            clearInterval(
                pollTimer
            );

            pollTimer =
                null;
        }
    }


    // ------------------------------------------------------------
    // 전체 분석 상태 표시명
    // ------------------------------------------------------------

    function formatAnalysisStatus(
        status
    ) {
        const labels = {
            ready:
                "준비",

            running:
                "분석 중",

            completed:
                "완료",

            failed:
                "실패",

            volume_required:
                "볼륨 선택 필요",
        };

        return (
            labels[status] ||
            String(status)
        );
    }


    // ------------------------------------------------------------
    // Stage 상태 업데이트
    // ------------------------------------------------------------

    function updateStages(
        stages
    ) {
        document
            .querySelectorAll(
                ".stage"
            )
            .forEach(
                (element) => {
                    const stageNumber =
                        element.dataset.stage;

                    const state =
                        stages[
                            stageNumber
                        ] ||
                        "waiting";

                    /*
                     * CSS와 내부 로직에서는
                     * 영문 상태값 유지.
                     */
                    element.dataset.state =
                        state;

                    const stateElement =
                        element.querySelector(
                            ".stage-state"
                        );

                    if (
                        stateElement
                    ) {
                        stateElement.textContent =
                            formatStageState(
                                state
                            );
                    }
                }
            );
    }


    // ------------------------------------------------------------
    // Stage 상태 표시명
    // ------------------------------------------------------------

    function formatStageState(
        state
    ) {
        const labels = {
            waiting:
                "대기",

            running:
                "진행 중",

            done:
                "완료",

            failed:
                "실패",
        };

        return (
            labels[state] ||
            state
        );
    }


    // ------------------------------------------------------------
    // Volume Selection 표시
    // ------------------------------------------------------------

    function showVolumeSelection(
        candidates
    ) {
        volumeList.innerHTML =
            "";

        selectedVolume =
            null;

        continueVolumeButton.disabled =
            true;

        if (
            !candidates.length
        ) {
            appendLog(
                "[UI 오류] 볼륨 선택이 필요하지만 NTFS 볼륨 후보 정보를 찾지 못했습니다."
            );

            return;
        }

        candidates.forEach(
            (candidate) => {
                const label =
                    document.createElement(
                        "label"
                    );

                label.className =
                    "volume-option";


                const radio =
                    document.createElement(
                        "input"
                    );

                radio.type =
                    "radio";

                radio.name =
                    "ntfs-volume";

                radio.value =
                    candidate.index;


                const content =
                    document.createElement(
                        "div"
                    );

                content.className =
                    "volume-option-content";


                const title =
                    document.createElement(
                        "div"
                    );

                title.className =
                    "volume-option-title";

                title.textContent =
                    `볼륨 ${candidate.index}`;


                const details =
                    document.createElement(
                        "div"
                    );

                details.className =
                    "volume-option-details";

                details.textContent =
                    `${candidate.size} · ${candidate.name}`;


                radio.addEventListener(
                    "change",
                    () => {
                        selectedVolume =
                            Number(
                                candidate.index
                            );

                        continueVolumeButton.disabled =
                            false;
                    }
                );


                content.appendChild(
                    title
                );

                content.appendChild(
                    details
                );

                label.appendChild(
                    radio
                );

                label.appendChild(
                    content
                );

                volumeList.appendChild(
                    label
                );
            }
        );


        volumePanel.hidden =
            false;

        volumePanel.scrollIntoView({
            behavior:
                "smooth",

            block:
                "center",
        });
    }


    // ------------------------------------------------------------
    // Volume Selection 숨기기
    // ------------------------------------------------------------

    function hideVolumeSelection() {
        volumePanel.hidden =
            true;

        volumeList.innerHTML =
            "";

        selectedVolume =
            null;

        continueVolumeButton.disabled =
            true;
    }


    // ------------------------------------------------------------
    // Live Log 자동 스크롤 여부
    // ------------------------------------------------------------

    function isLogNearBottom() {
        const threshold =
            40;

        const distanceFromBottom =
            log.scrollHeight -
            log.scrollTop -
            log.clientHeight;

        return (
            distanceFromBottom <=
            threshold
        );
    }


    // ------------------------------------------------------------
    // Live Log 전체 업데이트
    // ------------------------------------------------------------

    function updateLogs(
        logs
    ) {
        if (
            !Array.isArray(
                logs
            )
        ) {
            return;
        }

        /*
         * 사용자가 로그 맨 아래에 있을 때만
         * 새 로그를 자동으로 따라간다.
         *
         * 사용자가 과거 로그를 보기 위해
         * 위로 스크롤했다면 현재 위치를 유지한다.
         */
        const shouldAutoScroll =
            isLogNearBottom();

        const previousScrollTop =
            log.scrollTop;

        log.textContent =
            logs.join(
                "\n"
            );

        if (
            shouldAutoScroll
        ) {
            log.scrollTop =
                log.scrollHeight;

        } else {
            log.scrollTop =
                previousScrollTop;
        }
    }


    // ------------------------------------------------------------
    // Live Log 한 줄 추가
    // ------------------------------------------------------------

    function appendLog(
        message
    ) {
        const shouldAutoScroll =
            isLogNearBottom();

        const previousScrollTop =
            log.scrollTop;

        if (
            log.textContent
        ) {
            log.textContent +=
                "\n";
        }

        log.textContent +=
            message;

        if (
            shouldAutoScroll
        ) {
            log.scrollTop =
                log.scrollHeight;

        } else {
            log.scrollTop =
                previousScrollTop;
        }
    }


    // ------------------------------------------------------------
    // Errors API 조회
    // ------------------------------------------------------------

    async function updateErrors(
        caseId
    ) {
        try {
            const response =
                await fetch(
                    `/api/results/${encodeURIComponent(caseId)}/errors`
                );

            if (
                response.status ===
                404
            ) {
                return;
            }

            const data =
                await response.json();

            if (
                !response.ok
            ) {
                console.warn(
                    "오류 기록 조회 실패:",
                    data.detail ||
                    response.status
                );

                return;
            }

            renderErrors(
                data
            );

        } catch (error) {
            console.warn(
                "오류 기록 API 호출 실패:",
                error
            );
        }
    }


    // ------------------------------------------------------------
    // Errors 화면 렌더링
    // ------------------------------------------------------------

    function renderErrors(
        data
    ) {
        const summary =
            data.summary ||
            {};

        const events =
            Array.isArray(
                data.events
            )
                ? data.events
                : [];

        const total =
            Number(
                summary.total ||
                0
            );

        const retry =
            Number(
                summary.retry ||
                0
            );

        const skip =
            Number(
                summary.skip ||
                0
            );

        const abort =
            Number(
                summary.abort ||
                0
            );


        errorCount.textContent =
            `${total}건`;

        errorRetryCount.textContent =
            retry;

        errorSkipCount.textContent =
            skip;

        errorAbortCount.textContent =
            abort;


        if (
            abort > 0
        ) {
            errorCount.dataset.level =
                "danger";

        } else if (
            total > 0
        ) {
            errorCount.dataset.level =
                "warning";

        } else {
            errorCount.dataset.level =
                "success";
        }


        errorList.innerHTML =
            "";


        if (
            events.length ===
            0
        ) {
            const empty =
                document.createElement(
                    "div"
                );

            empty.id =
                "error-empty";

            empty.className =
                "error-empty";

            empty.textContent =
                "아직 기록된 오류가 없습니다.";

            errorList.appendChild(
                empty
            );

            return;
        }


        events.forEach(
            (event) => {
                errorList.appendChild(
                    createErrorEvent(
                        event
                    )
                );
            }
        );
    }


    // ------------------------------------------------------------
    // Error Event 한 건 생성
    // ------------------------------------------------------------

    function createErrorEvent(
        event
    ) {
        const detail =
            event.detail &&
            typeof event.detail ===
                "object"
                ? event.detail
                : {};

        const action =
            String(
                event.action ||
                "unknown"
            ).toLowerCase();


        const container =
            document.createElement(
                "article"
            );

        container.className =
            "error-event";

        container.dataset.action =
            action;


        const header =
            document.createElement(
                "div"
            );

        header.className =
            "error-event-header";


        const title =
            document.createElement(
                "div"
            );

        title.className =
            "error-event-title";


        const stage =
            document.createElement(
                "span"
            );

        stage.className =
            "error-stage";

        stage.textContent =
            formatErrorStage(
                event.stage
            );


        const type =
            document.createElement(
                "span"
            );

        type.className =
            "error-type";

        type.textContent =
            event.type ||
            "unknown";


        const actionBadge =
            document.createElement(
                "span"
            );

        actionBadge.className =
            "error-action";

        actionBadge.dataset.action =
            action;

        actionBadge.textContent =
            formatErrorAction(
                action
            );


        title.appendChild(
            stage
        );

        title.appendChild(
            type
        );

        header.appendChild(
            title
        );

        header.appendChild(
            actionBadge
        );


        const body =
            document.createElement(
                "div"
            );

        body.className =
            "error-event-body";


        if (
            detail.message
        ) {
            const message =
                document.createElement(
                    "p"
                );

            message.className =
                "error-message";

            message.textContent =
                String(
                    detail.message
                );

            body.appendChild(
                message
            );
        }


        const grid =
            document.createElement(
                "div"
            );

        grid.className =
            "error-detail-grid";


        addErrorDetail(
            grid,
            "Ref",
            detail.ref
        );

        addErrorDetail(
            grid,
            "필드",
            detail.field
        );

        addErrorDetail(
            grid,
            "값",
            detail.value
        );

        addErrorDetail(
            grid,
            "AI 주장값",
            detail.claimed,
            "claimed"
        );

        addErrorDetail(
            grid,
            "실제값",
            detail.actual,
            "actual"
        );

        addErrorDetail(
            grid,
            "파싱 오류",
            detail.parse_errors
        );

        addErrorDetail(
            grid,
            "레코드 수",
            detail.record_count
        );


        if (
            grid.children.length >
            0
        ) {
            body.appendChild(
                grid
            );
        }


        const meta =
            document.createElement(
                "div"
            );

        meta.className =
            "error-meta";


        if (
            event.attempt !==
                undefined &&
            event.attempt !==
                null
        ) {
            const attempt =
                document.createElement(
                    "span"
                );

            attempt.textContent =
                `시도 ${event.attempt}회`;

            meta.appendChild(
                attempt
            );
        }


        if (
            event.ts
        ) {
            const timestamp =
                document.createElement(
                    "span"
                );

            timestamp.textContent =
                formatTimestamp(
                    event.ts
                );

            meta.appendChild(
                timestamp
            );
        }


        if (
            detail.raw
        ) {
            const raw =
                document.createElement(
                    "span"
                );

            raw.textContent =
                `원문: ${detail.raw}`;

            meta.appendChild(
                raw
            );
        }


        if (
            meta.children.length >
            0
        ) {
            body.appendChild(
                meta
            );
        }


        container.appendChild(
            header
        );

        container.appendChild(
            body
        );

        return container;
    }


    // ------------------------------------------------------------
    // Error Detail 생성
    // ------------------------------------------------------------

    function addErrorDetail(
        parent,
        label,
        value,
        kind = null
    ) {
        if (
            value === undefined ||
            value === null ||
            value === ""
        ) {
            return;
        }


        const detail =
            document.createElement(
                "div"
            );

        detail.className =
            "error-detail";


        if (
            kind
        ) {
            detail.dataset.kind =
                kind;
        }


        const labelElement =
            document.createElement(
                "span"
            );

        labelElement.className =
            "error-detail-label";

        labelElement.textContent =
            label;


        const valueElement =
            document.createElement(
                "span"
            );

        valueElement.className =
            "error-detail-value";

        valueElement.textContent =
            formatErrorValue(
                value
            );


        detail.appendChild(
            labelElement
        );

        detail.appendChild(
            valueElement
        );

        parent.appendChild(
            detail
        );
    }


    // ------------------------------------------------------------
    // Error 값 표시
    // ------------------------------------------------------------

    function formatErrorValue(
        value
    ) {
        if (
            Array.isArray(
                value
            )
        ) {
            return value.join(
                "\n"
            );
        }

        if (
            typeof value ===
                "object" &&
            value !== null
        ) {
            try {
                return JSON.stringify(
                    value,
                    null,
                    2
                );

            } catch {
                return String(
                    value
                );
            }
        }

        if (
            typeof value ===
            "boolean"
        ) {
            return value
                ? "true"
                : "false";
        }

        return String(
            value
        );
    }


    // ------------------------------------------------------------
    // Error Stage 표시명
    // ------------------------------------------------------------

    function formatErrorStage(
        stage
    ) {
        const labels = {
            "01_input":
                "01 입력",

            "02_normalize":
                "02 정규화",

            "03_select":
                "03 아티팩트 선별",

            "04_parse":
                "04 파싱",

            "05_interpret":
                "05 근거 해석",

            "06_verify":
                "06 근거 검증",

            "07_report":
                "07 보고서 생성",

            ui:
                "UI",
        };

        return (
            labels[stage] ||
            stage ||
            "알 수 없는 Stage"
        );
    }


    // ------------------------------------------------------------
    // Error Action 표시명
    // ------------------------------------------------------------

    function formatErrorAction(
        action
    ) {
        const labels = {
            retry:
                "재시도",

            skip:
                "건너뜀",

            abort:
                "중단",
        };

        return (
            labels[action] ||
            String(action)
        );
    }


    // ------------------------------------------------------------
    // Timestamp 표시
    // ------------------------------------------------------------

    function formatTimestamp(
        value
    ) {
        const date =
            new Date(
                value
            );

        if (
            Number.isNaN(
                date.getTime()
            )
        ) {
            return String(
                value
            );
        }

        return date.toLocaleString(
            "ko-KR"
        );
    }


    // ------------------------------------------------------------
    // Final Report API 조회
    // ------------------------------------------------------------

    async function updateReport(
        caseId
    ) {
        try {
            const response =
                await fetch(
                    `/api/results/${encodeURIComponent(caseId)}/report`
                );

            if (
                response.status ===
                404
            ) {
                return;
            }

            const data =
                await response.json();

            if (
                !response.ok
            ) {
                console.warn(
                    "보고서 조회 실패:",
                    data.detail ||
                    response.status
                );

                return;
            }

            renderReport(
                data
            );

        } catch (error) {
            console.warn(
                "보고서 API 호출 실패:",
                error
            );
        }
    }


    // ------------------------------------------------------------
    // Final Report 화면 렌더링
    // ------------------------------------------------------------

    function renderReport(
        data
    ) {
        if (
            !data ||
            !data.exists
        ) {
            resetReport(
                "아직 생성된 07_report.md가 없습니다."
            );

            return;
        }

        reportFilename.textContent =
            data.filename ||
            "07_report.md";

        if (
            !window.ReportRenderer ||
            typeof window
                .ReportRenderer
                .renderInto !==
                "function"
        ) {
            resetReport(
                "보고서 렌더러를 불러오지 못했습니다."
            );

            appendLog(
                "[UI 오류] ReportRenderer를 사용할 수 없습니다."
            );

            return;
        }

        window.ReportRenderer.renderInto(
            reportContainer,
            data.content ||
            ""
        );
    }


    // ------------------------------------------------------------
    // Final Report 화면 초기화
    // ------------------------------------------------------------

    function resetReport(
        message =
            "Case를 불러오거나 분석을 완료하면 최종 보고서가 여기에 표시됩니다."
    ) {
        reportFilename.textContent =
            "불러온 보고서 없음";

        reportContainer.innerHTML =
            "";

        const empty =
            document.createElement(
                "div"
            );

        empty.id =
            "report-empty";

        empty.className =
            "report-empty";

        empty.textContent =
            message;

        reportContainer.appendChild(
            empty
        );
    }


    // ------------------------------------------------------------
    // Errors 화면 초기화
    // ------------------------------------------------------------

    function resetErrors() {
        errorCount.textContent =
            "0건";

        errorCount.dataset.level =
            "success";

        errorRetryCount.textContent =
            "0";

        errorSkipCount.textContent =
            "0";

        errorAbortCount.textContent =
            "0";

        errorList.innerHTML =
            "";

        const empty =
            document.createElement(
                "div"
            );

        empty.id =
            "error-empty";

        empty.className =
            "error-empty";

        empty.textContent =
            "아직 기록된 오류가 없습니다.";

        errorList.appendChild(
            empty
        );
    }


    // ------------------------------------------------------------
    // Stage 화면 초기화
    // ------------------------------------------------------------

    function resetStages() {
        document
            .querySelectorAll(
                ".stage"
            )
            .forEach(
                (element) => {
                    element.dataset.state =
                        "waiting";

                    const stateElement =
                        element.querySelector(
                            ".stage-state"
                        );

                    if (
                        stateElement
                    ) {
                        stateElement.textContent =
                            "대기";
                    }
                }
            );

        log.textContent =
            "";
    }
});