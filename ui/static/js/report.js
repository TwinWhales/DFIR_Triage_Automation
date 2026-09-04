window.ReportRenderer = (() => {

    /*
     * 지원 Evidence Reference
     *
     * 접두어 목록을 여기 적지 않는다. src/common/refs.py 가 원본이고,
     * ui/evidence_refs.py 를 거쳐 index.html 이 실어 보낸다. 손으로
     * 적었을 때 3종만 있어서 EVTX-SEC#... 이 눌리지 않았다.
     *
     * 예: MFT#12345 · USN#503461160 · EVTX-SEC#40912 · SYSMON#8817
     */
    const REF_PREFIXES =
        Array.isArray(window.EVIDENCE_REF_PREFIXES)
            ? window.EVIDENCE_REF_PREFIXES
            : [];


    if (!REF_PREFIXES.length) {
        // 폴백을 두지 않는다. 여기서 임의의 목록을 되살리면 서버가 보낸
        // 것과 어긋난 채로 일부만 눌리는, 방금 고친 그 상태가 된다.
        console.error(
            "[8vidence] Evidence Ref 접두어를 받지 못했습니다. " +
            "index.html 의 EVIDENCE_REF_PREFIXES 를 확인하십시오. " +
            "보고서의 ref 는 눌리지 않습니다."
        );
    }


    function escapeRegExp(value) {
        return value.replace(
            /[.*+?^${}()|[\]\\-]/g,
            "\\$&"
        );
    }


    /*
     * 접두어는 긴 것부터 온다 (ui/evidence_refs.py). 교대는 왼쪽부터
     * 맞춰 보므로 순서를 다시 정렬하면 안 된다.
     *
     * 뒤쪽 \b 를 쓰지 않는 이유: ref 값은 '.' 이나 ':' 로 끝날 수 있고
     * 그것은 단어 경계가 아니라, \b 를 붙이면 그런 ref 가 통째로 빠진다.
     */
    const EVIDENCE_REF_PATTERN =
        REF_PREFIXES.length
            ? new RegExp(
                "\\b(?:" +
                REF_PREFIXES
                    .map(escapeRegExp)
                    .join("|") +
                ")#[A-Za-z0-9._:-]+",
                "g"
            )
            : null;


    // ------------------------------------------------------------
    // HTML Escape
    // ------------------------------------------------------------

    function escapeHtml(value) {
        return String(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }


    // ------------------------------------------------------------
    // Evidence Ref 렌더링
    // ------------------------------------------------------------

    function renderEvidenceRefs(value) {
        if (!EVIDENCE_REF_PATTERN) {
            return value;
        }

        return value.replace(
            EVIDENCE_REF_PATTERN,
            (ref) => {
                const safeRef =
                    escapeHtml(ref);

                return (
                    `<button ` +
                    `type="button" ` +
                    `class="evidence-ref" ` +
                    `data-evidence-ref="${safeRef}" ` +
                    `title="Stage 04 원본 레코드 보기">` +
                    `${safeRef}` +
                    `</button>`
                );
            }
        );
    }


    // ------------------------------------------------------------
    // Inline Markdown
    // ------------------------------------------------------------

    function inlineMarkdown(text) {
        /*
         * 먼저 HTML Escape를 수행한다.
         *
         * 보고서 안의 임의 HTML이 브라우저에서
         * 직접 실행되지 않도록 한다.
         */
        let value =
            escapeHtml(text);


        // **bold**
        value = value.replace(
            /\*\*(.+?)\*\*/g,
            "<strong>$1</strong>"
        );


        // `inline code`
        value = value.replace(
            /`([^`]+)`/g,
            "<code>$1</code>"
        );


        // Evidence Reference
        value = renderEvidenceRefs(
            value
        );


        return value;
    }


    // ------------------------------------------------------------
    // Markdown Table 판별
    // ------------------------------------------------------------

    function isTableSeparator(line) {
        const trimmed =
            line.trim();


        if (!trimmed.startsWith("|")) {
            return false;
        }


        const cells =
            trimmed
                .slice(
                    1,
                    trimmed.endsWith("|")
                        ? -1
                        : undefined
                )
                .split("|")
                .map(
                    (cell) =>
                        cell.trim()
                );


        if (
            cells.length === 0
        ) {
            return false;
        }


        return cells.every(
            (cell) =>
                /^:?-{3,}:?$/.test(
                    cell
                )
        );
    }


    // ------------------------------------------------------------
    // Markdown Table Row 파싱
    // ------------------------------------------------------------

    function parseTableRow(line) {
        const trimmed =
            line.trim();


        const content =
            trimmed.startsWith("|")
                ? trimmed.slice(1)
                : trimmed;


        const withoutLastPipe =
            content.endsWith("|")
                ? content.slice(0, -1)
                : content;


        return withoutLastPipe
            .split("|")
            .map(
                (cell) =>
                    cell.trim()
            );
    }


    // ------------------------------------------------------------
    // Markdown Table 렌더링
    // ------------------------------------------------------------

    function renderTable(
        lines,
        startIndex
    ) {
        const headerCells =
            parseTableRow(
                lines[startIndex]
            );


        let index =
            startIndex + 2;


        const rows =
            [];


        while (
            index < lines.length &&
            lines[index]
                .trim()
                .startsWith("|")
        ) {
            rows.push(
                parseTableRow(
                    lines[index]
                )
            );

            index += 1;
        }


        let html =
            '<div class="report-table-wrapper">' +
            "<table>" +
            "<thead>" +
            "<tr>";


        headerCells.forEach(
            (cell) => {
                html +=
                    `<th>${
                        inlineMarkdown(
                            cell
                        )
                    }</th>`;
            }
        );


        html +=
            "</tr>" +
            "</thead>" +
            "<tbody>";


        rows.forEach(
            (row) => {

                html +=
                    "<tr>";


                headerCells.forEach(
                    (
                        _,
                        columnIndex
                    ) => {

                        const cell =
                            row[
                                columnIndex
                            ] ?? "";


                        html +=
                            `<td>${
                                inlineMarkdown(
                                    cell
                                )
                            }</td>`;
                    }
                );


                html +=
                    "</tr>";
            }
        );


        html +=
            "</tbody>" +
            "</table>" +
            "</div>";


        return {
            html,
            nextIndex: index,
        };
    }


    // ------------------------------------------------------------
    // Markdown 전체 렌더링
    // ------------------------------------------------------------

    function render(markdown) {
        if (!markdown) {
            return "";
        }


        const lines =
            String(markdown)
                .replace(
                    /\r\n/g,
                    "\n"
                )
                .split("\n");


        let html =
            "";

        let index =
            0;

        let paragraph =
            [];

        let listOpen =
            false;


        function flushParagraph() {
            if (
                paragraph.length ===
                0
            ) {
                return;
            }


            html +=
                `<p>${
                    inlineMarkdown(
                        paragraph.join(
                            " "
                        )
                    )
                }</p>`;


            paragraph =
                [];
        }


        function closeList() {
            if (
                !listOpen
            ) {
                return;
            }


            html +=
                "</ul>";

            listOpen =
                false;
        }


        while (
            index <
            lines.length
        ) {
            const rawLine =
                lines[index];

            const line =
                rawLine.trim();


            // 빈 줄
            if (!line) {
                flushParagraph();
                closeList();

                index += 1;

                continue;
            }


            // Markdown Table
            if (
                line.startsWith("|") &&
                index + 1 <
                    lines.length &&
                isTableSeparator(
                    lines[
                        index + 1
                    ]
                )
            ) {
                flushParagraph();
                closeList();


                const table =
                    renderTable(
                        lines,
                        index
                    );


                html +=
                    table.html;


                index =
                    table.nextIndex;


                continue;
            }


            // H1
            if (
                line.startsWith(
                    "# "
                )
            ) {
                flushParagraph();
                closeList();


                html +=
                    `<h1>${
                        inlineMarkdown(
                            line.slice(2)
                        )
                    }</h1>`;


                index += 1;

                continue;
            }


            // H2
            if (
                line.startsWith(
                    "## "
                )
            ) {
                flushParagraph();
                closeList();


                html +=
                    `<h2>${
                        inlineMarkdown(
                            line.slice(3)
                        )
                    }</h2>`;


                index += 1;

                continue;
            }


            // H3
            if (
                line.startsWith(
                    "### "
                )
            ) {
                flushParagraph();
                closeList();


                html +=
                    `<h3>${
                        inlineMarkdown(
                            line.slice(4)
                        )
                    }</h3>`;


                index += 1;

                continue;
            }


            // Horizontal Rule
            if (
                /^---+$/.test(
                    line
                )
            ) {
                flushParagraph();
                closeList();


                html +=
                    "<hr>";


                index += 1;

                continue;
            }


            // Unordered List
            if (
                line.startsWith(
                    "- "
                )
            ) {
                flushParagraph();


                if (
                    !listOpen
                ) {
                    html +=
                        "<ul>";

                    listOpen =
                        true;
                }


                html +=
                    `<li>${
                        inlineMarkdown(
                            line.slice(2)
                        )
                    }</li>`;


                index += 1;

                continue;
            }


            // 일반 문단
            closeList();


            paragraph.push(
                line
            );


            index += 1;
        }


        flushParagraph();
        closeList();


        return html;
    }


    // ------------------------------------------------------------
    // Report Container 렌더링
    // ------------------------------------------------------------

    function renderInto(
        container,
        markdown
    ) {
        if (!container) {
            return;
        }


        container.innerHTML =
            `<article class="report-document">${
                render(markdown)
            }</article>`;
    }


    // ============================================================
    // Evidence Detail
    // ============================================================


    // ------------------------------------------------------------
    // Evidence Ref 클릭 처리
    // ------------------------------------------------------------

    document.addEventListener(
        "click",
        async (event) => {

            const evidenceButton =
                event.target.closest(
                    ".evidence-ref"
                );


            if (
                !evidenceButton
            ) {
                return;
            }


            const ref =
                evidenceButton
                    .dataset
                    .evidenceRef;


            if (!ref) {
                return;
            }


            const caseIdInput =
                document.getElementById(
                    "case-id"
                );


            const caseId =
                caseIdInput
                    ? caseIdInput
                        .value
                        .trim()
                    : "";


            if (!caseId) {
                alert(
                    "근거를 조회할 Case ID가 없습니다."
                );

                return;
            }


            await loadEvidenceDetail(
                caseId,
                ref
            );
        }
    );


    // ------------------------------------------------------------
    // Evidence Detail 닫기
    // ------------------------------------------------------------

    document.addEventListener(
        "click",
        (event) => {

            const closeButton =
                event.target.closest(
                    "#evidence-close-button"
                );


            if (
                !closeButton
            ) {
                return;
            }


            hideEvidenceDetail();
        }
    );


    // ------------------------------------------------------------
    // Evidence Lookup API
    // ------------------------------------------------------------

    async function loadEvidenceDetail(
        caseId,
        ref
    ) {
        const panel =
            document.getElementById(
                "evidence-detail-panel"
            );

        const refElement =
            document.getElementById(
                "evidence-detail-ref"
            );

        const content =
            document.getElementById(
                "evidence-detail-content"
            );


        if (
            !panel ||
            !refElement ||
            !content
        ) {
            console.error(
                "근거 상세 UI를 찾을 수 없습니다."
            );

            return;
        }


        /*
         * 오른쪽 Drawer만 연다.
         *
         * scrollIntoView()를 호출하지 않는다.
         * 따라서 사용자가 보고 있던 보고서 위치는
         * 그대로 유지된다.
         */
        panel.hidden =
            false;


        refElement.textContent =
            ref;


        content.innerHTML =
            "";


        const loading =
            document.createElement(
                "div"
            );

        loading.className =
            "evidence-detail-loading";

        loading.textContent =
            "Stage 04 원본 레코드를 조회하고 있습니다...";


        content.appendChild(
            loading
        );


        try {
            const response =
                await fetch(
                    `/api/results/${
                        encodeURIComponent(
                            caseId
                        )
                    }/evidence/${
                        encodeURIComponent(
                            ref
                        )
                    }`
                );


            const data =
                await response.json();


            if (
                !response.ok
            ) {
                throw new Error(
                    data.detail ||
                    "근거 조회에 실패했습니다."
                );
            }


            renderEvidenceDetail(
                data
            );


        } catch (error) {

            renderEvidenceError(
                error.message
            );
        }
    }


    // ------------------------------------------------------------
    // Evidence Detail 렌더링
    // ------------------------------------------------------------

    function renderEvidenceDetail(
        data
    ) {
        const content =
            document.getElementById(
                "evidence-detail-content"
            );


        if (
            !content
        ) {
            return;
        }


        content.innerHTML =
            "";


        const meta =
            document.createElement(
                "div"
            );

        meta.className =
            "evidence-detail-meta";


        /*
         * Artifact, Offset, Timestamp는
         * DFIR에서 널리 사용하는 기술 용어이므로 유지한다.
         */
        addEvidenceMeta(
            meta,
            "Artifact",
            data.artifact
        );


        addEvidenceMeta(
            meta,
            "원본 파일",
            data.source_file
        );


        addEvidenceMeta(
            meta,
            "JSONL 라인",
            data.line_number
        );


        if (
            data.record &&
            data.record.offset !==
                undefined
        ) {
            addEvidenceMeta(
                meta,
                "Offset",
                data.record.offset
            );
        }


        if (
            data.record &&
            data.record.timestamp
        ) {
            addEvidenceMeta(
                meta,
                "Timestamp",
                data.record.timestamp
            );
        }


        content.appendChild(
            meta
        );


        const title =
            document.createElement(
                "h4"
            );

        title.className =
            "evidence-record-title";

        title.textContent =
            "Stage 04 원본 레코드";


        content.appendChild(
            title
        );


        const record =
            document.createElement(
                "pre"
            );

        record.className =
            "evidence-record";


        /*
         * 실제 Stage 04 JSONL 레코드는
         * 필드명과 값을 변형하지 않고 그대로 표시한다.
         *
         * evidence ref 추적의 신뢰성을 위해
         * 내부 JSON 자체는 번역하지 않는다.
         */
        record.textContent =
            JSON.stringify(
                data.record || {},
                null,
                2
            );


        content.appendChild(
            record
        );
    }


    // ------------------------------------------------------------
    // Evidence Metadata 생성
    // ------------------------------------------------------------

    function addEvidenceMeta(
        parent,
        label,
        value
    ) {
        if (
            value === undefined ||
            value === null ||
            value === ""
        ) {
            return;
        }


        const item =
            document.createElement(
                "div"
            );

        item.className =
            "evidence-detail-meta-item";


        const labelElement =
            document.createElement(
                "span"
            );

        labelElement.className =
            "evidence-detail-label";

        labelElement.textContent =
            label;


        const valueElement =
            document.createElement(
                "span"
            );

        valueElement.className =
            "evidence-detail-value";

        valueElement.textContent =
            String(value);


        item.appendChild(
            labelElement
        );

        item.appendChild(
            valueElement
        );


        parent.appendChild(
            item
        );
    }


    // ------------------------------------------------------------
    // Evidence 조회 오류
    // ------------------------------------------------------------

    function renderEvidenceError(
        message
    ) {
        const content =
            document.getElementById(
                "evidence-detail-content"
            );


        if (
            !content
        ) {
            return;
        }


        content.innerHTML =
            "";


        const error =
            document.createElement(
                "div"
            );

        error.className =
            "evidence-detail-error";

        error.textContent =
            message ||
            "근거 조회 중 오류가 발생했습니다.";


        content.appendChild(
            error
        );
    }


    // ------------------------------------------------------------
    // Evidence Detail 닫기
    // ------------------------------------------------------------

    function hideEvidenceDetail() {
        const panel =
            document.getElementById(
                "evidence-detail-panel"
            );

        const refElement =
            document.getElementById(
                "evidence-detail-ref"
            );

        const content =
            document.getElementById(
                "evidence-detail-content"
            );


        if (
            panel
        ) {
            panel.hidden =
                true;
        }


        if (
            refElement
        ) {
            refElement.textContent =
                "";
        }


        if (
            content
        ) {
            content.innerHTML =
                "";
        }
    }


    // ------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------

    return {
        render,
        renderInto,
    };

})();