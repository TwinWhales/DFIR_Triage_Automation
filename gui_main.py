import html
import json
import os
import shutil
import subprocess
import sys
import time

from collections import Counter
from pathlib import Path
from urllib.parse import quote, unquote

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from pipeline_worker import PipelineWorker


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.project_root = Path(__file__).resolve().parent

        self.worker = None
        self.analysis_start_time = None
        self.stage_start_time = None
        self.pause_started_at = None
        self.paused_total = 0.0
        self.current_stage_name = "대기 중"
        self.analysis_state = "IDLE"

        self.elapsed_timer = QTimer(self)
        self.elapsed_timer.setInterval(1000)
        self.elapsed_timer.timeout.connect(self.update_elapsed_time)

        # ref -> parsed evidence
        self.evidence_records = {}

        # 검색 이전 전체 Evidence 목록
        self.all_evidence_refs = []

        # =================================================
        # Window
        # =================================================

        self.setWindowTitle("8vidence")
        self.resize(1150, 900)

        icon_path = (
            self.project_root
            / "assets"
            / "8vidence.ico"
        )

        if icon_path.exists():
            self.setWindowIcon(
                QIcon(str(icon_path))
            )

        # =================================================
        # Central Widget
        # =================================================

        central_widget = QWidget()

        self.setCentralWidget(
            central_widget
        )

        main_layout = QVBoxLayout(
            central_widget
        )

        main_layout.setContentsMargins(
            10,
            10,
            10,
            10
        )

        # =================================================
        # Main Vertical Splitter
        # =================================================

        self.main_splitter = QSplitter(
            Qt.Vertical
        )

        self.main_splitter.setHandleWidth(8)
        self.main_splitter.setChildrenCollapsible(False)

        main_layout.addWidget(
            self.main_splitter
        )

        # =================================================
        # TOP : Input Panel
        # =================================================

        self.input_panel = QWidget()

        input_layout = QVBoxLayout(
            self.input_panel
        )

        input_layout.setContentsMargins(
            4,
            4,
            4,
            4
        )

        # -------------------------------------------------
        # Header
        # -------------------------------------------------

        title = QLabel("8vidence")

        title.setStyleSheet(
            "font-size: 30px;"
            "font-weight: bold;"
        )

        subtitle = QLabel(
            "Evidence-driven DFIR Triage"
        )

        subtitle.setStyleSheet(
            "font-size: 13px;"
            "color: gray;"
        )

        input_layout.addWidget(
            title
        )

        input_layout.addWidget(
            subtitle
        )

        # -------------------------------------------------
        # Case ID
        # -------------------------------------------------

        input_layout.addWidget(
            QLabel("Case ID")
        )

        self.case_input = QLineEdit()

        self.case_input.setPlaceholderText(
            "예: C-001"
        )

        input_layout.addWidget(
            self.case_input
        )

        # -------------------------------------------------
        # Resizable Input Area
        # -------------------------------------------------

        # Incident Description과 하단 분석 도구 영역 사이를
        # 마우스로 직접 드래그해 높이를 조절할 수 있다.
        self.input_content_splitter = QSplitter(Qt.Vertical)
        self.input_content_splitter.setHandleWidth(8)
        self.input_content_splitter.setChildrenCollapsible(False)

        # Incident Description section
        incident_section = QWidget()
        incident_layout = QVBoxLayout(incident_section)
        incident_layout.setContentsMargins(0, 0, 0, 0)

        incident_layout.addWidget(
            QLabel("Incident Description")
        )

        self.incident_input = QTextEdit()

        self.incident_input.setPlaceholderText(
            "EDR/SIEM 경보 또는 초동 조사 내용을 자연어로 입력하세요.\n"
            "예: 웹 서버에서 의심스러운 ASPX 파일 생성과 "
            "신규 로컬 계정 생성 정황이 확인되었습니다."
        )

        self.incident_input.setMinimumHeight(80)
        incident_layout.addWidget(self.incident_input)

        # Analysis controls section
        controls_section = QWidget()
        controls_layout = QVBoxLayout(controls_section)
        controls_layout.setContentsMargins(0, 0, 0, 0)

        # Evidence Directory
        controls_layout.addWidget(
            QLabel("Evidence Directory")
        )

        evidence_path_layout = QHBoxLayout()

        self.evidence_input = QLineEdit()
        self.evidence_input.setPlaceholderText(
            "분석할 Evidence 폴더를 선택하세요."
        )

        browse_button = QPushButton("찾기")
        browse_button.clicked.connect(
            self.select_evidence_directory
        )

        evidence_path_layout.addWidget(self.evidence_input)
        evidence_path_layout.addWidget(browse_button)
        controls_layout.addLayout(evidence_path_layout)

        # Analysis Mode
        controls_layout.addWidget(QLabel("분석 모드"))

        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "테스트 모드 (Stub)",
            "실제 AI 분석 (Ollama)",
        ])
        controls_layout.addWidget(self.mode_combo)

        # Analysis Profile / optimized backend parameters
        controls_layout.addWidget(QLabel("분석 프로필"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItem(
            "빠른 분석 · 15건 / ctx 8K / 캐시",
            {
                "name": "빠른 분석",
                "stage05_limit": 15,
                "stage02_num_ctx": 8192,
                "stage05_num_ctx": 8192,
                "stage05_max_list_items": 10,
                "use_stage04_cache": True,
            },
        )
        self.profile_combo.addItem(
            "표준 분석 · 40건 / ctx 16K / 캐시",
            {
                "name": "표준 분석",
                "stage05_limit": 40,
                "stage02_num_ctx": 16384,
                "stage05_num_ctx": 16384,
                "stage05_max_list_items": 20,
                "use_stage04_cache": True,
            },
        )
        self.profile_combo.addItem(
            "심층 분석 · 60건 / ctx 32K / 재파싱",
            {
                "name": "심층 분석",
                "stage05_limit": 60,
                "stage02_num_ctx": 32768,
                "stage05_num_ctx": 32768,
                "stage05_max_list_items": 20,
                "use_stage04_cache": False,
            },
        )
        self.profile_combo.setToolTip(
            "빠른/표준은 같은 Case ID·증적·선별 결과의 Stage 04 파싱 캐시를 재사용합니다. "
            "심층 분석은 매번 실제 증적을 다시 파싱합니다."
        )
        self.profile_combo.setCurrentIndex(0)
        controls_layout.addWidget(self.profile_combo)

        # Runtime controls
        button_layout = QHBoxLayout()

        self.start_button = QPushButton("▶ 분석 시작")
        self.start_button.setMinimumHeight(42)
        self.start_button.clicked.connect(self.start_analysis)

        self.pause_button = QPushButton("⏸ 일시정지")
        self.pause_button.setMinimumHeight(42)
        self.pause_button.setEnabled(False)
        self.pause_button.clicked.connect(self.pause_analysis)

        self.resume_button = QPushButton("▶ 재개")
        self.resume_button.setMinimumHeight(42)
        self.resume_button.setEnabled(False)
        self.resume_button.clicked.connect(self.resume_analysis)

        self.stop_button = QPushButton("■ 정지")
        self.stop_button.setMinimumHeight(42)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_analysis)

        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.pause_button)
        button_layout.addWidget(self.resume_button)
        button_layout.addWidget(self.stop_button)
        controls_layout.addLayout(button_layout)

        # Runtime status
        self.stage_status_label = QLabel("현재 단계: 대기 중")
        self.elapsed_label = QLabel("총 경과: 00:00:00    현재 단계: 00:00:00")
        controls_layout.addWidget(self.stage_status_label)
        controls_layout.addWidget(self.elapsed_label)

        # Progress
        controls_layout.addWidget(QLabel("진행률"))

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        controls_layout.addWidget(self.progress_bar)

        self.input_content_splitter.addWidget(incident_section)
        self.input_content_splitter.addWidget(controls_section)
        self.input_content_splitter.setStretchFactor(0, 2)
        self.input_content_splitter.setStretchFactor(1, 1)
        self.input_content_splitter.setSizes([180, 170])

        input_layout.addWidget(self.input_content_splitter)

        # =================================================
        # BOTTOM : Tabs
        # =================================================

        self.tabs = QTabWidget()

        # =================================================
        # Summary Tab
        # =================================================

        self.summary_tab = QWidget()

        summary_layout = QVBoxLayout(
            self.summary_tab
        )

        summary_header = QHBoxLayout()
        summary_header.addStretch()

        self.summary_expand_button = QPushButton("⛶ 크게 보기")
        self.summary_expand_button.setToolTip("Summary를 최대화된 별도 창으로 엽니다.")
        self.summary_expand_button.clicked.connect(
            lambda: self.open_large_text_view(
                "8vidence — Summary",
                self.summary_output,
                enable_evidence_links=True,
            )
        )
        summary_header.addWidget(self.summary_expand_button)
        summary_layout.addLayout(summary_header)

        self.summary_output = QTextBrowser()

        self.summary_output.setOpenLinks(
            False
        )

        self.summary_output.anchorClicked.connect(
            self.handle_evidence_link
        )

        self.summary_output.setPlaceholderText(
            "분석 완료 후 주요 Finding과 검증 결과가 표시됩니다."
        )

        summary_layout.addWidget(
            self.summary_output
        )

        self.tabs.addTab(
            self.summary_tab,
            "Summary"
        )

        # =================================================
        # Timeline Tab
        # =================================================

        self.timeline_tab = QWidget()

        timeline_layout = QVBoxLayout(
            self.timeline_tab
        )

        timeline_header = QHBoxLayout()
        timeline_header.addStretch()

        self.timeline_expand_button = QPushButton("⛶ 크게 보기")
        self.timeline_expand_button.setToolTip("Timeline을 최대화된 별도 창으로 엽니다.")
        self.timeline_expand_button.clicked.connect(
            lambda: self.open_large_text_view(
                "8vidence — Timeline",
                self.timeline_output,
                enable_evidence_links=True,
            )
        )
        timeline_header.addWidget(self.timeline_expand_button)
        timeline_layout.addLayout(timeline_header)

        self.timeline_output = QTextBrowser()

        self.timeline_output.setOpenLinks(
            False
        )

        self.timeline_output.anchorClicked.connect(
            self.handle_evidence_link
        )

        self.timeline_output.setPlaceholderText(
            "Incident Timeline이 표시됩니다."
        )

        timeline_layout.addWidget(
            self.timeline_output
        )

        self.tabs.addTab(
            self.timeline_tab,
            "Timeline"
        )

        # =================================================
        # Evidence Tab
        # =================================================

        self.evidence_tab = QWidget()

        evidence_tab_layout = QVBoxLayout(
            self.evidence_tab
        )

        evidence_title = QLabel(
            "Evidence Explorer"
        )

        evidence_title.setStyleSheet(
            "font-size: 16px;"
            "font-weight: bold;"
        )

        evidence_tab_layout.addWidget(
            evidence_title
        )

        evidence_hint = QLabel(
            "Summary 또는 Timeline의 Evidence Reference를 클릭하면 "
            "해당 원본 레코드로 바로 이동합니다."
        )

        evidence_hint.setStyleSheet(
            "color: gray;"
        )

        evidence_tab_layout.addWidget(
            evidence_hint
        )

        # -------------------------------------------------
        # Horizontal Splitter
        # -------------------------------------------------

        self.evidence_splitter = QSplitter(
            Qt.Horizontal
        )

        self.evidence_splitter.setHandleWidth(
            7
        )

        # Left Evidence List
        self.evidence_list = QListWidget()

        self.evidence_list.setMinimumWidth(
            190
        )

        # Windows Explorer 스타일 다중 선택
        # Ctrl + 클릭: 개별 다중 선택
        # Shift + 클릭: 범위 선택
        self.evidence_list.setSelectionMode(
            QAbstractItemView.ExtendedSelection
        )

        # 다중 선택은 유지하되, 오른쪽 패널은 마지막으로 클릭한
        # 단일 Evidence의 상세 정보만 유지한다. 다중 분석은 우클릭 메뉴에서 실행한다.
        self.evidence_list.itemClicked.connect(
            self.show_evidence_detail
        )

        self.evidence_list.setContextMenuPolicy(
            Qt.CustomContextMenu
        )
        self.evidence_list.customContextMenuRequested.connect(
            self.show_evidence_context_menu
        )

        # Right Evidence Detail
        self.evidence_detail = QTextBrowser()

        self.evidence_detail.setPlaceholderText(
            "왼쪽 Evidence Reference를 선택하세요."
        )

        self.evidence_splitter.addWidget(
            self.evidence_list
        )

        self.evidence_splitter.addWidget(
            self.evidence_detail
        )

        self.evidence_splitter.setStretchFactor(
            0,
            1
        )

        self.evidence_splitter.setStretchFactor(
            1,
            4
        )

        self.evidence_splitter.setSizes([
            240,
            760
        ])

        evidence_tab_layout.addWidget(
            self.evidence_splitter
        )

        self.tabs.addTab(
            self.evidence_tab,
            "Evidence"
        )

        # =================================================
        # Report Tab
        # =================================================

        self.report_tab = QWidget()

        report_layout = QVBoxLayout(
            self.report_tab
        )

        report_header = QHBoxLayout()
        report_header.addStretch()

        self.report_expand_button = QPushButton("⛶ 크게 보기")
        self.report_expand_button.setToolTip("Report를 최대화된 별도 창으로 엽니다.")
        self.report_expand_button.clicked.connect(
            lambda: self.open_large_text_view(
                "8vidence — Report",
                self.report_output,
            )
        )
        report_header.addWidget(self.report_expand_button)
        report_layout.addLayout(report_header)

        self.report_output = QTextBrowser()

        self.report_output.setPlaceholderText(
            "최종 DFIR Report가 표시됩니다."
        )

        report_layout.addWidget(
            self.report_output
        )

        self.tabs.addTab(
            self.report_tab,
            "Report"
        )

        # =================================================
        # Log Tab
        # =================================================

        self.log_tab = QWidget()

        log_layout = QVBoxLayout(
            self.log_tab
        )

        log_header = QHBoxLayout()
        log_header.addStretch()

        self.log_expand_button = QPushButton("⛶ 크게 보기")
        self.log_expand_button.setToolTip("Log를 최대화된 별도 창으로 엽니다.")
        self.log_expand_button.clicked.connect(
            lambda: self.open_large_text_view(
                "8vidence — Log",
                self.log_output,
                plain_text=True,
            )
        )
        log_header.addWidget(self.log_expand_button)
        log_layout.addLayout(log_header)

        self.log_output = QTextEdit()

        self.log_output.setReadOnly(
            True
        )

        log_layout.addWidget(
            self.log_output
        )

        self.tabs.addTab(
            self.log_tab,
            "Log"
        )

        # =================================================
        # Main Splitter
        # =================================================

        self.main_splitter.addWidget(
            self.input_panel
        )

        self.main_splitter.addWidget(
            self.tabs
        )

        self.main_splitter.setStretchFactor(
            0,
            1
        )

        self.main_splitter.setStretchFactor(
            1,
            3
        )

        self.main_splitter.setSizes([
            360,
            540
        ])

        # =================================================
        # Menu
        # =================================================

        self.create_menu()

        # =================================================
        # Status Bar
        # =================================================

        self.statusBar().showMessage(
            "Ready"
        )

    # =====================================================
    # Menu
    # =====================================================

    def create_menu(self):

        menu_bar = self.menuBar()

        # =================================================
        # File
        # =================================================

        file_menu = menu_bar.addMenu(
            "File"
        )

        open_evidence_action = QAction(
            "Open Evidence Directory...",
            self
        )

        open_evidence_action.triggered.connect(
            self.select_evidence_directory
        )

        file_menu.addAction(
            open_evidence_action
        )

        open_case_action = QAction(
            "Open Case...",
            self
        )

        open_case_action.triggered.connect(
            self.open_case
        )

        file_menu.addAction(
            open_case_action
        )

        file_menu.addSeparator()

        export_report_action = QAction(
            "Export Report...",
            self
        )

        export_report_action.triggered.connect(
            self.export_report
        )

        file_menu.addAction(
            export_report_action
        )

        file_menu.addSeparator()

        exit_action = QAction(
            "Exit",
            self
        )

        exit_action.triggered.connect(
            self.close
        )

        file_menu.addAction(
            exit_action
        )

        # =================================================
        # Analysis
        # =================================================

        analysis_menu = menu_bar.addMenu(
            "Analysis"
        )

        self.start_action = QAction(
            "Start Analysis",
            self
        )

        self.start_action.triggered.connect(
            self.start_analysis
        )

        analysis_menu.addAction(
            self.start_action
        )

        self.rerun_action = QAction(
            "Re-run Analysis",
            self
        )

        self.rerun_action.triggered.connect(
            self.start_analysis
        )

        analysis_menu.addAction(
            self.rerun_action
        )

        # =================================================
        # Evidence
        # =================================================

        evidence_menu = menu_bar.addMenu(
            "Evidence"
        )

        explorer_action = QAction(
            "Evidence Explorer",
            self
        )

        explorer_action.triggered.connect(
            lambda: self.tabs.setCurrentWidget(
                self.evidence_tab
            )
        )

        evidence_menu.addAction(
            explorer_action
        )

        search_action = QAction(
            "Search Evidence...",
            self
        )

        search_action.triggered.connect(
            self.search_evidence
        )

        evidence_menu.addAction(
            search_action
        )

        summary_action = QAction(
            "Artifact Summary",
            self
        )

        summary_action.triggered.connect(
            self.show_artifact_summary
        )

        evidence_menu.addAction(
            summary_action
        )

        evidence_menu.addSeparator()

        analyze_selected_action = QAction(
            "Analyze Selected Evidence",
            self
        )

        analyze_selected_action.triggered.connect(
            self.analyze_selected_evidence
        )

        evidence_menu.addAction(
            analyze_selected_action
        )

        clear_selection_action = QAction(
            "Clear Selection",
            self
        )

        clear_selection_action.triggered.connect(
            self.clear_evidence_selection
        )

        evidence_menu.addAction(
            clear_selection_action
        )

        evidence_menu.addSeparator()

        refresh_action = QAction(
            "Refresh Evidence",
            self
        )

        refresh_action.triggered.connect(
            self.refresh_evidence_list
        )

        evidence_menu.addAction(
            refresh_action
        )

        # =================================================
        # View
        # =================================================

        view_menu = menu_bar.addMenu(
            "View"
        )

        self.input_panel_action = QAction(
            "Input Panel",
            self
        )

        self.input_panel_action.setCheckable(
            True
        )

        self.input_panel_action.setChecked(
            True
        )

        self.input_panel_action.triggered.connect(
            self.toggle_input_panel
        )

        view_menu.addAction(
            self.input_panel_action
        )

        self.status_bar_action = QAction(
            "Status Bar",
            self
        )

        self.status_bar_action.setCheckable(
            True
        )

        self.status_bar_action.setChecked(
            True
        )

        self.status_bar_action.triggered.connect(
            self.toggle_status_bar
        )

        view_menu.addAction(
            self.status_bar_action
        )

        view_menu.addSeparator()

        summary_tab_action = QAction(
            "Summary",
            self
        )

        summary_tab_action.triggered.connect(
            lambda: self.tabs.setCurrentWidget(
                self.summary_tab
            )
        )

        view_menu.addAction(
            summary_tab_action
        )

        timeline_tab_action = QAction(
            "Timeline",
            self
        )

        timeline_tab_action.triggered.connect(
            lambda: self.tabs.setCurrentWidget(
                self.timeline_tab
            )
        )

        view_menu.addAction(
            timeline_tab_action
        )

        evidence_tab_action = QAction(
            "Evidence",
            self
        )

        evidence_tab_action.triggered.connect(
            lambda: self.tabs.setCurrentWidget(
                self.evidence_tab
            )
        )

        view_menu.addAction(
            evidence_tab_action
        )

        report_tab_action = QAction(
            "Report",
            self
        )

        report_tab_action.triggered.connect(
            lambda: self.tabs.setCurrentWidget(
                self.report_tab
            )
        )

        view_menu.addAction(
            report_tab_action
        )

        log_tab_action = QAction(
            "Log",
            self
        )

        log_tab_action.triggered.connect(
            lambda: self.tabs.setCurrentWidget(
                self.log_tab
            )
        )

        view_menu.addAction(
            log_tab_action
        )

        view_menu.addSeparator()

        expand_current_action = QAction(
            "현재 탭 크게 보기",
            self
        )
        expand_current_action.setShortcut("Ctrl+Shift+F")
        expand_current_action.triggered.connect(
            self.open_current_tab_large
        )
        view_menu.addAction(expand_current_action)

        # =================================================
        # Tools
        # =================================================

        tools_menu = menu_bar.addMenu(
            "Tools"
        )

        open_case_folder_action = QAction(
            "Open Case Folder",
            self
        )

        open_case_folder_action.triggered.connect(
            self.open_case_folder
        )

        tools_menu.addAction(
            open_case_folder_action
        )

        open_evidence_folder_action = QAction(
            "Open Evidence Folder",
            self
        )

        open_evidence_folder_action.triggered.connect(
            self.open_evidence_folder
        )

        tools_menu.addAction(
            open_evidence_folder_action
        )

        # =================================================
        # Help
        # =================================================

        help_menu = menu_bar.addMenu(
            "Help"
        )

        pipeline_action = QAction(
            "Pipeline Information",
            self
        )

        pipeline_action.triggered.connect(
            self.show_pipeline_information
        )

        help_menu.addAction(
            pipeline_action
        )

        help_menu.addSeparator()

        about_action = QAction(
            "About 8vidence",
            self
        )

        about_action.triggered.connect(
            self.show_about
        )

        help_menu.addAction(
            about_action
        )

    # =====================================================
    # Helpers
    # =====================================================

    def get_case_id(self):

        return (
            self.case_input
            .text()
            .strip()
            .upper()
        )

    def get_case_dir(self):

        case_id = self.get_case_id()

        if not case_id:
            return None

        return (
            self.project_root
            / "cases"
            / case_id
        )

    def open_path_in_system(self, path):

        path = Path(path)

        if not path.exists():

            QMessageBox.warning(
                self,
                "Path Not Found",
                f"경로를 찾을 수 없습니다.\n\n{path}"
            )

            return

        try:

            if sys.platform.startswith(
                "win"
            ):

                os.startfile(
                    str(path)
                )

            elif sys.platform == "darwin":

                subprocess.Popen([
                    "open",
                    str(path)
                ])

            else:

                subprocess.Popen([
                    "xdg-open",
                    str(path)
                ])

        except Exception as e:

            QMessageBox.critical(
                self,
                "Open Failed",
                str(e)
            )

    # =====================================================
    # Select Evidence
    # =====================================================

    def select_evidence_directory(self):

        folder = QFileDialog.getExistingDirectory(
            self,
            "Evidence Directory 선택"
        )

        if folder:

            self.evidence_input.setText(
                folder
            )

            self.statusBar().showMessage(
                "Evidence Directory 선택 완료"
            )

    # =====================================================
    # Open Existing Case
    # =====================================================

    def open_case(self):

        cases_root = (
            self.project_root
            / "cases"
        )

        cases_root.mkdir(
            exist_ok=True
        )

        folder = QFileDialog.getExistingDirectory(
            self,
            "Case Folder 선택",
            str(cases_root)
        )

        if not folder:
            return

        case_dir = Path(folder)

        case_id = case_dir.name.upper()

        findings_file = (
            case_dir
            / "05_findings.json"
        )

        if not findings_file.exists():

            QMessageBox.warning(
                self,
                "Invalid Case",
                (
                    "선택한 폴더에서 "
                    "05_findings.json을 찾을 수 없습니다."
                )
            )

            return

        self.case_input.setText(
            case_id
        )

        # -------------------------------------------------
        # Try restoring original input
        # -------------------------------------------------

        input_file = (
            case_dir
            / "01_input.json"
        )

        if input_file.exists():

            try:

                with input_file.open(
                    "r",
                    encoding="utf-8"
                ) as f:

                    input_data = json.load(f)

                possible_incident_keys = [
                    "incident_description",
                    "incident",
                    "description",
                    "alert",
                    "summary",
                ]

                for key in possible_incident_keys:

                    value = input_data.get(
                        key
                    )

                    if isinstance(
                        value,
                        str
                    ) and value.strip():

                        self.incident_input.setPlainText(
                            value
                        )

                        break

                possible_evidence_keys = [
                    "evidence_dir",
                    "evidence",
                    "evidence_path",
                ]

                for key in possible_evidence_keys:

                    value = input_data.get(
                        key
                    )

                    if isinstance(
                        value,
                        str
                    ) and value.strip():

                        self.evidence_input.setText(
                            value
                        )

                        break

            except Exception:
                pass

        # -------------------------------------------------
        # Load case outputs
        # -------------------------------------------------

        self.load_evidence()
        self.load_results()
        self.load_report()

        self.progress_bar.setValue(
            100
        )

        self.stage_status_label.setText("현재 단계: 완료")

        self.tabs.setCurrentWidget(
            self.summary_tab
        )

        self.statusBar().showMessage(
            f"Case Loaded : {case_id}"
        )

    # =====================================================
    # Export Report
    # =====================================================

    def export_report(self):

        case_dir = self.get_case_dir()

        if case_dir is None:

            QMessageBox.warning(
                self,
                "Case Required",
                "먼저 Case를 선택하거나 분석하세요."
            )

            return

        source_file = (
            case_dir
            / "07_report.md"
        )

        if not source_file.exists():

            QMessageBox.warning(
                self,
                "Report Not Found",
                "07_report.md가 존재하지 않습니다."
            )

            return

        default_name = (
            f"{self.get_case_id()}_8vidence_report.md"
        )

        target_file, _ = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            str(
                self.project_root
                / default_name
            ),
            "Markdown Report (*.md)"
        )

        if not target_file:
            return

        try:

            shutil.copy2(
                source_file,
                target_file
            )

            self.statusBar().showMessage(
                "Report Export Complete"
            )

            QMessageBox.information(
                self,
                "Export Complete",
                (
                    "보고서를 저장했습니다.\n\n"
                    f"{target_file}"
                )
            )

        except Exception as e:

            QMessageBox.critical(
                self,
                "Export Failed",
                str(e)
            )

    # =====================================================
    # Large View
    # =====================================================

    def open_large_text_view(
        self,
        title,
        source_widget,
        enable_evidence_links=False,
        plain_text=False,
    ):
        """현재 탭의 내용을 최대화된 별도 창으로 표시한다."""

        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(1200, 850)

        layout = QVBoxLayout(dialog)

        viewer = QTextBrowser()
        viewer.setOpenExternalLinks(False)

        if plain_text:
            viewer.setPlainText(source_widget.toPlainText())
        else:
            viewer.setHtml(source_widget.toHtml())

        if enable_evidence_links:
            viewer.setOpenLinks(False)
            viewer.anchorClicked.connect(self.handle_evidence_link)

        layout.addWidget(viewer)

        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        dialog.setWindowState(dialog.windowState() | Qt.WindowMaximized)
        dialog.exec()

    def open_current_tab_large(self):
        current = self.tabs.currentWidget()

        if current is self.summary_tab:
            self.open_large_text_view(
                "8vidence — Summary",
                self.summary_output,
                enable_evidence_links=True,
            )
        elif current is self.timeline_tab:
            self.open_large_text_view(
                "8vidence — Timeline",
                self.timeline_output,
                enable_evidence_links=True,
            )
        elif current is self.report_tab:
            self.open_large_text_view(
                "8vidence — Report",
                self.report_output,
            )
        elif current is self.log_tab:
            self.open_large_text_view(
                "8vidence — Log",
                self.log_output,
                plain_text=True,
            )
        elif current is self.evidence_tab:
            QMessageBox.information(
                self,
                "크게 보기",
                "Evidence 탭은 가운데 구분선을 드래그하여 목록/상세 영역을 조절할 수 있습니다.",
            )

    # =====================================================
    # Start Analysis
    # =====================================================

    def start_analysis(self):

        if self.worker is not None and self.worker.isRunning():
            QMessageBox.information(
                self,
                "Analysis Running",
                "이미 분석이 실행 중입니다. 일시정지·재개·정지 버튼을 사용하세요."
            )
            return

        case_id = self.get_case_id()

        incident_description = (
            self.incident_input
            .toPlainText()
            .strip()
        )

        evidence_dir = (
            self.evidence_input
            .text()
            .strip()
        )

        mode = (
            self.mode_combo
            .currentText()
        )

        profile = self.profile_combo.currentData() or {
            "name": "빠른 분석",
            "stage05_limit": 15,
            "stage02_num_ctx": 8192,
            "stage05_num_ctx": 8192,
            "stage05_max_list_items": 10,
            "use_stage04_cache": True,
        }

        # -------------------------------------------------
        # Validation
        # -------------------------------------------------

        if not case_id:

            self.log_output.append(
                "[ERROR] Case ID를 입력하세요."
            )

            self.tabs.setCurrentWidget(
                self.log_tab
            )

            return

        if not incident_description:

            self.log_output.append(
                "[ERROR] Incident Description을 입력하세요."
            )

            self.tabs.setCurrentWidget(
                self.log_tab
            )

            return

        if not evidence_dir:

            self.log_output.append(
                "[ERROR] Evidence Directory를 선택하세요."
            )

            self.tabs.setCurrentWidget(
                self.log_tab
            )

            return

        # -------------------------------------------------
        # Reset UI
        # -------------------------------------------------

        self.log_output.clear()
        self.summary_output.clear()
        self.timeline_output.clear()
        self.report_output.clear()

        self.evidence_list.clear()
        self.evidence_detail.clear()

        self.evidence_records = {}
        self.all_evidence_refs = []

        self.progress_bar.setValue(
            0
        )

        self.set_analysis_controls("RUNNING")

        self.analysis_start_time = time.monotonic()
        self.stage_start_time = self.analysis_start_time
        self.pause_started_at = None
        self.paused_total = 0.0
        self.current_stage_name = "준비 중"
        self.stage_status_label.setText("현재 단계: 준비 중")
        self.elapsed_label.setText("총 경과: 00:00:00    현재 단계: 00:00:00")
        self.elapsed_timer.start()

        self.tabs.setCurrentWidget(
            self.log_tab
        )

        self.statusBar().showMessage(
            "Analysis Running..."
        )

        # -------------------------------------------------
        # Worker
        # -------------------------------------------------

        self.worker = PipelineWorker(
            case_id=case_id,
            incident_description=incident_description,
            evidence_dir=evidence_dir,
            mode=mode,
            stage05_limit=profile["stage05_limit"],
            stage02_num_ctx=profile["stage02_num_ctx"],
            stage05_num_ctx=profile["stage05_num_ctx"],
            stage05_max_list_items=profile["stage05_max_list_items"],
            use_stage04_cache=profile["use_stage04_cache"],
            profile_name=profile["name"],
        )

        self.worker.log.connect(
            self.log_output.append
        )

        self.worker.progress.connect(
            self.progress_bar.setValue
        )

        self.worker.finished.connect(
            self.analysis_finished
        )

        self.worker.error.connect(
            self.analysis_error
        )

        self.worker.stopped.connect(
            self.analysis_stopped
        )

        self.worker.state_changed.connect(
            self.handle_worker_state
        )

        self.worker.stage_changed.connect(
            self.handle_stage_changed
        )

        self.worker.start()

    # =====================================================
    # Analysis Runtime Control
    # =====================================================

    def set_analysis_controls(self, state):
        self.analysis_state = state
        running = state in {"RUNNING", "PAUSING"}
        paused = state == "PAUSED"
        busy = running or paused or state == "STOPPING"

        self.start_button.setEnabled(not busy)
        self.start_action.setEnabled(not busy)
        if hasattr(self, "rerun_action"):
            self.rerun_action.setEnabled(not busy)

        self.pause_button.setEnabled(running and state != "PAUSING")
        self.resume_button.setEnabled(paused)
        self.stop_button.setEnabled(busy and state != "STOPPING")

        self.mode_combo.setEnabled(not busy)
        self.profile_combo.setEnabled(not busy)

    def pause_analysis(self):
        if self.worker is None or not self.worker.isRunning():
            return
        self.set_analysis_controls("PAUSING")
        self.statusBar().showMessage("Pausing Analysis...")
        self.worker.request_pause()

    def resume_analysis(self):
        if self.worker is None or not self.worker.isRunning():
            return

        if self.pause_started_at is not None:
            paused_for = time.monotonic() - self.pause_started_at
            self.paused_total += paused_for
            if self.analysis_start_time is not None:
                self.analysis_start_time += paused_for
            if self.stage_start_time is not None:
                self.stage_start_time += paused_for
            self.pause_started_at = None

        self.worker.request_resume()
        self.set_analysis_controls("RUNNING")
        self.statusBar().showMessage("Analysis Running...")

    def stop_analysis(self):
        if self.worker is None or not self.worker.isRunning():
            return

        answer = QMessageBox.question(
            self,
            "Stop Analysis",
            "현재 분석을 중지할까요?\n완료된 Stage 산출물은 케이스 폴더에 남습니다.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return

        self.set_analysis_controls("STOPPING")
        self.statusBar().showMessage("Stopping Analysis...")
        self.worker.request_stop()

    def analysis_stopped(self):
        self.elapsed_timer.stop()
        self.set_analysis_controls("STOPPED")
        self.update_elapsed_time()
        self.stage_status_label.setText(
            f"현재 단계: {self.current_stage_name} · 중지됨"
        )
        self.statusBar().showMessage("Analysis Stopped")
        self.tabs.setCurrentWidget(self.log_tab)

    def handle_worker_state(self, state):
        if state == "PAUSED":
            if self.pause_started_at is None:
                self.pause_started_at = time.monotonic()
            self.set_analysis_controls("PAUSED")
            self.stage_status_label.setText(
                f"현재 단계: {self.current_stage_name} · 일시정지"
            )
            self.statusBar().showMessage("Analysis Paused")
        elif state == "RUNNING":
            self.set_analysis_controls("RUNNING")
        elif state == "STOPPING":
            self.set_analysis_controls("STOPPING")

    def handle_stage_changed(self, stage_name, stage_number):
        self.current_stage_name = stage_name
        self.stage_start_time = time.monotonic()
        self.stage_status_label.setText(
            f"현재 단계: {stage_name} ({stage_number}/7)"
        )

    def update_elapsed_time(self):
        if self.analysis_start_time is None:
            return

        now = time.monotonic()
        if self.pause_started_at is not None:
            now = self.pause_started_at

        total_seconds = max(0, int(now - self.analysis_start_time))
        stage_seconds = 0
        if self.stage_start_time is not None:
            stage_seconds = max(0, int(now - self.stage_start_time))

        self.elapsed_label.setText(
            f"총 경과: {self.format_duration(total_seconds)}    "
            f"현재 단계: {self.format_duration(stage_seconds)}"
        )

    @staticmethod
    def format_duration(seconds):
        hours, rem = divmod(int(seconds), 3600)
        minutes, secs = divmod(rem, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    # =====================================================
    # Analysis Finished
    # =====================================================

    def analysis_finished(self):

        self.elapsed_timer.stop()
        self.set_analysis_controls("COMPLETED")
        self.update_elapsed_time()

        self.statusBar().showMessage(
            "Analysis Complete"
        )

        self.load_evidence()
        self.load_results()
        self.load_report()

        self.tabs.setCurrentWidget(
            self.summary_tab
        )

    # =====================================================
    # Load Results
    # =====================================================

    def load_results(self):

        case_dir = self.get_case_dir()

        if case_dir is None:
            return

        findings_file = (
            case_dir
            / "05_findings.json"
        )

        verified_file = (
            case_dir
            / "06_verified.json"
        )

        if not findings_file.exists():

            self.summary_output.setPlainText(
                "05_findings.json을 찾을 수 없습니다."
            )

            return

        try:

            with findings_file.open(
                "r",
                encoding="utf-8"
            ) as f:

                findings_data = json.load(
                    f
                )

        except Exception as e:

            self.summary_output.setPlainText(
                f"Findings 로드 실패:\n{e}"
            )

            return

        verified_data = {}

        if verified_file.exists():

            try:

                with verified_file.open(
                    "r",
                    encoding="utf-8"
                ) as f:

                    verified_data = json.load(
                        f
                    )

            except Exception:
                verified_data = {}

        self.load_summary(
            findings_data,
            verified_data
        )

        self.load_timeline(
            findings_data
        )

    # =====================================================
    # Evidence Link
    # =====================================================

    def make_evidence_link(
        self,
        ref
    ):

        encoded_ref = quote(
            ref,
            safe=""
        )

        safe_ref = html.escape(
            ref
        )

        return (
            f'<a href="ref://{encoded_ref}">'
            f'{safe_ref}'
            f'</a>'
        )

    # =====================================================
    # Summary
    # =====================================================

    def load_summary(
        self,
        findings_data,
        verified_data
    ):

        case_id = findings_data.get(
            "case_id",
            "-"
        )

        generator = findings_data.get(
            "generator",
            "-"
        )

        stats = verified_data.get(
            "stats",
            {}
        )

        passed = stats.get(
            "passed",
            len(
                verified_data.get(
                    "passed",
                    []
                )
            )
        )

        rejected = stats.get(
            "rejected",
            len(
                verified_data.get(
                    "rejected",
                    []
                )
            )
        )

        unverifiable = stats.get(
            "unverifiable",
            len(
                verified_data.get(
                    "unverifiable",
                    []
                )
            )
        )

        hallucination_rate = stats.get(
            "hallucination_rate",
            0
        )

        findings = findings_data.get(
            "findings",
            []
        )

        parts = []

        parts.append(
            "<h2>8vidence Analysis Summary</h2>"
        )

        parts.append(
            f"""
            <p>
                <b>Case ID:</b>
                {html.escape(str(case_id))}
                <br>

                <b>LLM / Engine:</b>
                {html.escape(str(generator))}
            </p>
            """
        )

        parts.append(
            "<h3>Verification</h3>"
        )

        parts.append(
            f"""
            <table cellpadding="6">
                <tr>
                    <td><b>Passed</b></td>
                    <td>{passed}</td>
                </tr>
                <tr>
                    <td><b>Rejected</b></td>
                    <td>{rejected}</td>
                </tr>
                <tr>
                    <td><b>Unverifiable</b></td>
                    <td>{unverifiable}</td>
                </tr>
                <tr>
                    <td><b>Hallucination Rate</b></td>
                    <td>{hallucination_rate}</td>
                </tr>
            </table>
            """
        )

        parts.append(
            "<h3>Findings</h3>"
        )

        for finding in findings:

            finding_id = finding.get(
                "id",
                "-"
            )

            severity = finding.get(
                "severity",
                "-"
            )

            technique = finding.get(
                "technique"
            )

            statement = finding.get(
                "statement",
                ""
            )

            refs = finding.get(
                "refs",
                []
            )

            severity_upper = str(
                severity
            ).upper()

            parts.append(
                "<hr>"
            )

            parts.append(
                f"""
                <h3>
                    [{html.escape(severity_upper)}]
                    {html.escape(str(finding_id))}
                </h3>
                """
            )

            parts.append(
                f"""
                <p>
                    <b>MITRE ATT&amp;CK:</b>
                    {html.escape(str(technique or "-"))}
                </p>
                """
            )

            if statement:

                parts.append(
                    f"""
                    <p>
                        {html.escape(str(statement))}
                    </p>
                    """
                )

            if refs:

                parts.append(
                    "<p><b>Evidence</b></p>"
                )

                parts.append(
                    "<ul>"
                )

                for ref in refs:

                    parts.append(
                        "<li>"
                        + self.make_evidence_link(
                            ref
                        )
                        + "</li>"
                    )

                parts.append(
                    "</ul>"
                )

            else:

                parts.append(
                    """
                    <p>
                        <b>Evidence:</b>
                        없음 / 종합 판단
                    </p>
                    """
                )

        self.summary_output.setHtml(
            "".join(parts)
        )

    # =====================================================
    # Timeline
    # =====================================================

    def load_timeline(
        self,
        findings_data
    ):

        timeline = findings_data.get(
            "timeline",
            []
        )

        if not timeline:

            self.timeline_output.setPlainText(
                "Timeline 데이터가 없습니다."
            )

            return

        timeline = sorted(
            timeline,
            key=lambda x: x.get(
                "ts",
                ""
            )
        )

        parts = []

        parts.append(
            "<h2>Incident Timeline</h2>"
        )

        for index, event in enumerate(
            timeline
        ):

            ts = event.get(
                "ts",
                "-"
            )

            event_name = event.get(
                "event",
                "-"
            )

            refs = event.get(
                "refs",
                []
            )

            parts.append(
                "<hr>"
            )

            parts.append(
                f"""
                <h3>
                    {html.escape(str(ts))}
                </h3>

                <p>
                    {html.escape(str(event_name))}
                </p>
                """
            )

            if refs:

                evidence_links = []

                for ref in refs:

                    evidence_links.append(
                        self.make_evidence_link(
                            ref
                        )
                    )

                parts.append(
                    """
                    <p>
                        <b>Evidence:</b>
                        """
                    + ", ".join(
                        evidence_links
                    )
                    + """
                    </p>
                    """
                )

            if index < len(timeline) - 1:

                parts.append(
                    """
                    <p style="font-size:20px;">
                        ↓
                    </p>
                    """
                )

        self.timeline_output.setHtml(
            "".join(parts)
        )

    # =====================================================
    # Evidence Click
    # =====================================================

    def handle_evidence_link(
        self,
        url
    ):

        url_text = url.toString()

        if not url_text.startswith(
            "ref://"
        ):
            return

        encoded_ref = url_text.split(
            "ref://",
            1
        )[1]

        ref = unquote(
            encoded_ref
        )

        self.open_evidence_ref(
            ref
        )

    # =====================================================
    # Open Evidence Ref
    # =====================================================

    def open_evidence_ref(
        self,
        ref
    ):

        if ref not in self.evidence_records:

            QMessageBox.warning(
                self,
                "Evidence Not Found",
                (
                    f"{ref}\n\n"
                    "해당 Reference가 "
                    "04_parsed에서 확인되지 않았습니다."
                )
            )

            return

        # 검색으로 필터된 상태일 수도 있으므로
        # 전체 목록으로 복원
        self.refresh_evidence_list(
            select_ref=ref
        )

        self.tabs.setCurrentWidget(
            self.evidence_tab
        )

    # =====================================================
    # Load Evidence
    # =====================================================

    def load_evidence(self):

        case_dir = self.get_case_dir()

        if case_dir is None:
            return

        parsed_dir = (
            case_dir
            / "04_parsed"
        )

        self.evidence_records = {}
        self.all_evidence_refs = []

        self.evidence_list.clear()
        self.evidence_detail.clear()

        if not parsed_dir.exists():

            self.evidence_detail.setPlainText(
                "04_parsed 폴더를 찾을 수 없습니다."
            )

            return

        jsonl_files = list(
            parsed_dir.glob(
                "*.jsonl"
            )
        )

        for jsonl_file in jsonl_files:

            try:

                with jsonl_file.open(
                    "r",
                    encoding="utf-8"
                ) as f:

                    for line in f:

                        line = line.strip()

                        if not line:
                            continue

                        try:

                            record = json.loads(
                                line
                            )

                        except json.JSONDecodeError:
                            continue

                        ref = record.get(
                            "ref"
                        )

                        if not ref:
                            continue

                        self.evidence_records[
                            ref
                        ] = {
                            "source": jsonl_file.name,
                            "record": record,
                        }

            except Exception:
                continue

        self.all_evidence_refs = sorted(
            self.evidence_records.keys()
        )

        self.refresh_evidence_list()

    # =====================================================
    # Refresh Evidence List
    # =====================================================

    def refresh_evidence_list(
        self,
        select_ref=None
    ):

        self.evidence_list.clear()

        if not self.all_evidence_refs:

            self.evidence_detail.setPlainText(
                "표시할 parsed Evidence가 없습니다."
            )

            return

        for ref in self.all_evidence_refs:

            self.evidence_list.addItem(
                ref
            )

        if select_ref:

            for index in range(
                self.evidence_list.count()
            ):

                item = self.evidence_list.item(
                    index
                )

                if item.text() == select_ref:

                    self.evidence_list.setCurrentRow(
                        index
                    )

                    self.evidence_list.scrollToItem(
                        item
                    )

                    return

        self.evidence_list.setCurrentRow(
            0
        )

        # itemSelectionChanged 시그널이 상세 화면을 갱신함

    # =====================================================
    # Search Evidence
    # =====================================================

    def search_evidence(self):

        if not self.evidence_records:

            QMessageBox.information(
                self,
                "Search Evidence",
                (
                    "현재 로드된 Evidence가 없습니다.\n"
                    "먼저 Case를 분석하거나 Open Case를 사용하세요."
                )
            )

            return

        keyword, ok = QInputDialog.getText(
            self,
            "Search Evidence",
            (
                "검색할 키워드를 입력하세요.\n\n"
                "예: svc_backup, shell.aspx, 4720"
            )
        )

        if not ok:
            return

        keyword = keyword.strip()

        if not keyword:
            return

        keyword_lower = keyword.lower()

        matched_refs = []

        for ref, evidence in (
            self.evidence_records.items()
        ):

            record = evidence.get(
                "record",
                {}
            )

            searchable_text = (
                json.dumps(
                    record,
                    ensure_ascii=False
                )
                .lower()
            )

            source = str(
                evidence.get(
                    "source",
                    ""
                )
            ).lower()

            if (
                keyword_lower in searchable_text
                or keyword_lower in ref.lower()
                or keyword_lower in source
            ):

                matched_refs.append(
                    ref
                )

        matched_refs.sort()

        if not matched_refs:

            QMessageBox.information(
                self,
                "Search Evidence",
                (
                    f"'{keyword}'와 일치하는 "
                    "Evidence가 없습니다."
                )
            )

            return

        self.evidence_list.clear()

        for ref in matched_refs:

            self.evidence_list.addItem(
                ref
            )

        self.tabs.setCurrentWidget(
            self.evidence_tab
        )

        self.evidence_list.setCurrentRow(
            0
        )

        self.statusBar().showMessage(
            f"Evidence Search : {len(matched_refs)} result(s)"
        )

    # =====================================================
    # Artifact Summary
    # =====================================================

    def show_artifact_summary(self):

        if not self.evidence_records:

            QMessageBox.information(
                self,
                "Artifact Summary",
                "현재 로드된 Evidence가 없습니다."
            )

            return

        artifact_counter = Counter()
        flag_counter = Counter()

        for evidence in (
            self.evidence_records.values()
        ):

            record = evidence.get(
                "record",
                {}
            )

            artifact = record.get(
                "artifact",
                "unknown"
            )

            artifact_counter[
                artifact
            ] += 1

            flags = record.get(
                "flags",
                []
            )

            for flag in flags:

                flag_counter[
                    flag
                ] += 1

        total_records = len(
            self.evidence_records
        )

        flagged_records = 0

        for evidence in (
            self.evidence_records.values()
        ):

            record = evidence.get(
                "record",
                {}
            )

            if record.get(
                "flags"
            ):

                flagged_records += 1

        parts = []

        parts.append(
            "<h2>Artifact Summary</h2>"
        )

        parts.append(
            f"""
            <p>
                <b>Case:</b>
                {html.escape(self.get_case_id())}
            </p>

            <p>
                <b>Parsed Records:</b>
                {total_records}
                <br>

                <b>Flagged Records:</b>
                {flagged_records}
            </p>
            """
        )

        parts.append(
            "<h3>Artifacts</h3>"
        )

        parts.append(
            "<table cellpadding='5'>"
        )

        for artifact, count in (
            artifact_counter.most_common()
        ):

            parts.append(
                f"""
                <tr>
                    <td>
                        {html.escape(str(artifact))}
                    </td>

                    <td>
                        {count}
                    </td>
                </tr>
                """
            )

        parts.append(
            "</table>"
        )

        if flag_counter:

            parts.append(
                "<h3>Flags</h3>"
            )

            parts.append(
                "<table cellpadding='5'>"
            )

            for flag, count in (
                flag_counter.most_common()
            ):

                parts.append(
                    f"""
                    <tr>
                        <td>
                            {html.escape(str(flag))}
                        </td>

                        <td>
                            {count}
                        </td>
                    </tr>
                    """
                )

            parts.append(
                "</table>"
            )

        QMessageBox.information(
            self,
            "Artifact Summary",
            "".join(parts)
        )

    # =====================================================
    # Evidence Multi Selection
    # =====================================================

    def get_selected_evidence_refs(self):

        return [
            item.text()
            for item in self.evidence_list.selectedItems()
            if item.text() in self.evidence_records
        ]

    def clear_evidence_selection(self):

        self.evidence_list.clearSelection()
        self.evidence_detail.setHtml(
            "<h2>Evidence Explorer</h2>"
            "<p>선택이 해제되었습니다. "
            "Ctrl + 클릭 또는 Shift + 클릭으로 여러 Evidence를 선택한 뒤 "
            "우클릭하여 Compare / Timeline / Correlation 기능을 사용할 수 있습니다.</p>"
        )

        self.statusBar().showMessage(
            "Evidence Selection Cleared"
        )

    def show_selected_evidence(self):

        # 호환용 메서드. 다중 선택 시 오른쪽 패널을 자동으로 바꾸지 않는다.
        # 현재 선택 항목 중 currentItem만 단일 상세로 표시한다.
        item = self.evidence_list.currentItem()
        if item is not None:
            self.show_evidence_detail(item)

    def get_evidence_timestamp(self, record):

        # EVTX 등 일반 파서 레코드
        for key in (
            "timestamp",
            "ts",
            "time",
            "datetime",
        ):
            value = record.get(key)
            if value:
                return str(value)

        # $MFT 계열
        for key in (
            "si_ctime",
            "fn_ctime",
            "si_mtime",
            "fn_mtime",
        ):
            value = record.get(key)
            if value:
                return str(value)

        return "-"

    def build_selected_evidence_correlation(self, selected_refs):

        events = []

        for ref in selected_refs:
            evidence = self.evidence_records.get(ref, {})
            record = evidence.get("record", {})
            artifact = str(record.get("artifact", "unknown"))
            timestamp = self.get_evidence_timestamp(record)

            summary = ""

            if artifact.startswith("evtx:"):
                event_id = record.get("event_id", "-")
                fields = record.get("fields", {})

                if event_id == 4720:
                    target = fields.get("TargetUserName", "알 수 없는 계정")
                    summary = f"신규 로컬 계정 '{target}' 생성"

                elif event_id == 4732:
                    group = fields.get("TargetUserName", "알 수 없는 그룹")
                    member = fields.get("MemberName", "알 수 없는 계정")
                    summary = f"'{member}' 계정이 '{group}' 그룹에 추가"

                else:
                    summary = f"Windows Event ID {event_id} 기록"

            elif artifact == "$MFT":
                path = record.get("path", "알 수 없는 파일")
                flags = record.get("flags", [])
                summary = f"파일 '{path}'의 $MFT 레코드 확인"
                if "timestamp_mismatch" in flags:
                    summary += " (timestamp_mismatch)"

            else:
                summary = self.interpret_evidence(record)

            events.append({
                "ref": ref,
                "timestamp": timestamp,
                "artifact": artifact,
                "summary": summary,
            })

        events.sort(
            key=lambda x: (
                x["timestamp"] == "-",
                x["timestamp"],
                x["ref"],
            )
        )

        detected = []

        has_mft_suspicious = any(
            e["artifact"] == "$MFT" and "timestamp_mismatch" in e["summary"]
            for e in events
        )

        has_account_create = any(
            "신규 로컬 계정" in e["summary"]
            for e in events
        )

        has_priv_add = any(
            "그룹에 추가" in e["summary"]
            for e in events
        )

        if has_mft_suspicious and has_account_create and has_priv_add:
            detected.append(
                "의심 파일 흔적 이후 신규 계정 생성 및 권한 그룹 추가가 함께 선택되었습니다. "
                "선택된 증거만으로 공격 인과관계를 확정할 수는 없지만, "
                "웹셸 또는 파일 기반 초기 침해 이후 계정 생성·권한 확보로 이어지는 후속 행위 가능성을 우선 검토할 수 있습니다."
            )
        elif has_account_create and has_priv_add:
            detected.append(
                "신규 계정 생성과 권한 그룹 추가 이벤트가 함께 선택되었습니다. "
                "두 이벤트의 대상 계정과 시간 간격을 비교하여 비인가 계정 생성 및 권한 상승 정황인지 확인할 필요가 있습니다."
            )
        elif len(events) >= 2:
            detected.append(
                "여러 Evidence가 선택되었습니다. 아래 시간순 비교를 바탕으로 공통 사용자, 파일 경로, 호스트, "
                "Event ID 및 Flags의 연관성을 확인하십시오."
            )

        return events, detected

    def show_multiple_evidence_detail(self, selected_refs):

        events, detected = self.build_selected_evidence_correlation(
            selected_refs
        )

        parts = [
            f"<h2>Selected Evidence ({len(selected_refs)} records)</h2>",
            "<p><b>Multi-record comparison</b></p>",
            "<p>Ctrl + 클릭 또는 Shift + 클릭으로 선택한 Evidence를 한 화면에서 비교합니다.</p>",
        ]

        if detected:
            parts.append("<h3>Rule-based Correlation Preview</h3>")
            for message in detected:
                parts.append(
                    f"<p>{html.escape(message)}</p>"
                )

        parts.append("<hr>")
        parts.append("<h3>Timeline Comparison</h3>")
        parts.append(
            "<table cellpadding='6' cellspacing='0' border='1'>"
            "<tr>"
            "<th>Timestamp</th>"
            "<th>Reference</th>"
            "<th>Artifact</th>"
            "<th>Summary</th>"
            "</tr>"
        )

        for event in events:
            parts.append(
                "<tr>"
                f"<td>{html.escape(str(event['timestamp']))}</td>"
                f"<td>{html.escape(str(event['ref']))}</td>"
                f"<td>{html.escape(str(event['artifact']))}</td>"
                f"<td>{html.escape(str(event['summary']))}</td>"
                "</tr>"
            )

        parts.append("</table>")
        parts.append("<hr>")
        parts.append("<h3>Selected References</h3><ul>")

        for ref in selected_refs:
            parts.append(
                f"<li>{html.escape(ref)}</li>"
            )

        parts.append("</ul>")
        parts.append(
            "<p><i>현재 상관분석은 Rule-based Preview입니다. "
            "추후 Ollama 연결 시 동일한 선택 레코드를 sLLM에 전달하여 "
            "Evidence 간 관계와 공격 흐름을 해석하도록 확장할 수 있습니다.</i></p>"
        )

        self.evidence_detail.setHtml(
            "".join(parts)
        )

        self.statusBar().showMessage(
            f"Selected Evidence : {len(selected_refs)} record(s)"
        )

    def show_evidence_context_menu(self, pos):

        selected_refs = self.get_selected_evidence_refs()

        if not selected_refs:
            return

        menu = QMenu(self)

        if len(selected_refs) == 1:
            open_action = menu.addAction("Open Evidence Detail")
            menu.addSeparator()
        else:
            open_action = None

        compare_action = menu.addAction(
            f"Compare Selected Evidence ({len(selected_refs)})"
        )
        timeline_action = menu.addAction("Sort by Time")
        correlation_action = menu.addAction("Correlation View")

        menu.addSeparator()

        ollama_action = menu.addAction("Analyze with Ollama")
        ollama_action.setEnabled(False)
        ollama_action.setToolTip(
            "Ollama 연동 단계에서 활성화됩니다."
        )

        menu.addSeparator()

        copy_action = menu.addAction("Copy References")
        export_action = menu.addAction("Export Selected Evidence...")

        action = menu.exec(
            self.evidence_list.mapToGlobal(pos)
        )

        if action is None:
            return

        if open_action is not None and action == open_action:
            item = self.evidence_list.currentItem()
            self.show_evidence_detail(item)
        elif action == compare_action:
            self.show_selected_compare_window(selected_refs)
        elif action == timeline_action:
            self.show_selected_timeline_window(selected_refs)
        elif action == correlation_action:
            self.show_selected_correlation_window(selected_refs)
        elif action == copy_action:
            self.copy_selected_evidence_refs(selected_refs)
        elif action == export_action:
            self.export_selected_evidence(selected_refs)

    def create_evidence_dialog(self, title, html_content, width=900, height=650):

        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(width, height)

        layout = QVBoxLayout(dialog)

        browser = QTextBrowser()
        browser.setHtml(html_content)
        layout.addWidget(browser)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Close
        )
        buttons.rejected.connect(dialog.reject)
        buttons.clicked.connect(dialog.accept)
        layout.addWidget(buttons)

        dialog.exec()

    def show_selected_compare_window(self, selected_refs=None):

        if selected_refs is None:
            selected_refs = self.get_selected_evidence_refs()

        if len(selected_refs) < 2:
            QMessageBox.information(
                self,
                "Compare Selected Evidence",
                "비교할 Evidence를 2개 이상 선택하세요."
            )
            return

        events, _ = self.build_selected_evidence_correlation(
            selected_refs
        )

        parts = [
            f"<h2>Evidence Comparison ({len(events)} records)</h2>",
            "<p>선택한 Evidence의 핵심 정보를 한 화면에서 비교합니다.</p>",
            "<table cellpadding='6' cellspacing='0' border='1'>",
            "<tr><th>Timestamp</th><th>Reference</th><th>Artifact</th>"
            "<th>Event / Path</th><th>Flags</th></tr>",
        ]

        for event in events:
            ref = event["ref"]
            record = self.evidence_records.get(ref, {}).get("record", {})
            artifact = str(record.get("artifact", "-"))

            if artifact.startswith("evtx:"):
                key_value = f"Event ID {record.get('event_id', '-')}"
            elif artifact == "$MFT":
                key_value = str(record.get("path", "-"))
            else:
                key_value = event["summary"]

            flags = ", ".join(
                str(flag) for flag in record.get("flags", [])
            ) or "-"

            parts.append(
                "<tr>"
                f"<td>{html.escape(str(event['timestamp']))}</td>"
                f"<td>{html.escape(str(ref))}</td>"
                f"<td>{html.escape(artifact)}</td>"
                f"<td>{html.escape(key_value)}</td>"
                f"<td>{html.escape(flags)}</td>"
                "</tr>"
            )

        parts.append("</table>")

        self.create_evidence_dialog(
            "8vidence — Compare Selected Evidence",
            "".join(parts),
            width=1000,
            height=650,
        )

    def show_selected_timeline_window(self, selected_refs=None):

        if selected_refs is None:
            selected_refs = self.get_selected_evidence_refs()

        if len(selected_refs) < 2:
            QMessageBox.information(
                self,
                "Sort by Time",
                "시간순으로 볼 Evidence를 2개 이상 선택하세요."
            )
            return

        events, _ = self.build_selected_evidence_correlation(
            selected_refs
        )

        parts = [
            f"<h2>Selected Evidence Timeline ({len(events)} records)</h2>",
            "<p>선택된 Evidence만 Timestamp 기준으로 정렬했습니다.</p>",
        ]

        for index, event in enumerate(events):
            parts.append("<hr>")
            parts.append(
                f"<h3>{html.escape(str(event['timestamp']))}</h3>"
                f"<p><b>{html.escape(str(event['ref']))}</b> &nbsp; "
                f"[{html.escape(str(event['artifact']))}]</p>"
                f"<p>{html.escape(str(event['summary']))}</p>"
            )
            if index < len(events) - 1:
                parts.append("<p style='font-size:20px;'>↓</p>")

        self.create_evidence_dialog(
            "8vidence — Selected Evidence Timeline",
            "".join(parts),
            width=850,
            height=700,
        )

    def show_selected_correlation_window(self, selected_refs=None):

        if selected_refs is None:
            selected_refs = self.get_selected_evidence_refs()

        if len(selected_refs) < 2:
            QMessageBox.information(
                self,
                "Correlation View",
                "상관분석할 Evidence를 2개 이상 선택하세요."
            )
            return

        events, detected = self.build_selected_evidence_correlation(
            selected_refs
        )

        parts = [
            f"<h2>Correlation View ({len(events)} records)</h2>",
            "<p><b>Rule-based correlation preview</b></p>",
        ]

        if detected:
            for message in detected:
                parts.append(
                    f"<p>{html.escape(message)}</p>"
                )
        else:
            parts.append(
                "<p>현재 규칙에서 뚜렷한 상관 패턴이 식별되지 않았습니다. "
                "시간, 사용자, 호스트, 경로 및 Flags를 추가로 확인하세요.</p>"
            )

        parts.append("<hr><h3>Evidence Flow</h3>")

        for event in events:
            parts.append(
                f"<p><b>{html.escape(str(event['timestamp']))}</b><br>"
                f"{html.escape(str(event['ref']))} — "
                f"{html.escape(str(event['summary']))}</p>"
            )

        parts.append(
            "<hr><p><i>이 화면은 현재 Rule-based 결과입니다. "
            "Ollama 연결 후 선택 Evidence만 sLLM에 전달하는 기능으로 확장합니다.</i></p>"
        )

        self.create_evidence_dialog(
            "8vidence — Correlation View",
            "".join(parts),
            width=850,
            height=650,
        )

    def copy_selected_evidence_refs(self, selected_refs=None):

        if selected_refs is None:
            selected_refs = self.get_selected_evidence_refs()

        if not selected_refs:
            return

        QApplication.clipboard().setText(
            "\n".join(selected_refs)
        )
        self.statusBar().showMessage(
            f"Copied {len(selected_refs)} Evidence reference(s)"
        )

    def export_selected_evidence(self, selected_refs=None):

        if selected_refs is None:
            selected_refs = self.get_selected_evidence_refs()

        if not selected_refs:
            return

        default_name = (
            f"{self.get_case_id() or 'CASE'}_selected_evidence.json"
        )

        target_file, _ = QFileDialog.getSaveFileName(
            self,
            "Export Selected Evidence",
            str(self.project_root / default_name),
            "JSON (*.json)"
        )

        if not target_file:
            return

        payload = []
        for ref in selected_refs:
            evidence = self.evidence_records.get(ref, {})
            payload.append({
                "ref": ref,
                "source": evidence.get("source", "-"),
                "record": evidence.get("record", {}),
            })

        try:
            Path(target_file).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            self.statusBar().showMessage(
                f"Selected Evidence Exported : {len(payload)} record(s)"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Failed",
                str(e)
            )

    def analyze_selected_evidence(self):

        selected_refs = self.get_selected_evidence_refs()

        if len(selected_refs) < 2:
            QMessageBox.information(
                self,
                "Analyze Selected Evidence",
                "Evidence를 2개 이상 선택하세요.\n\n"
                "Ctrl + 클릭: 개별 다중 선택\n"
                "Shift + 클릭: 범위 선택"
            )
            return

        self.show_selected_correlation_window(
            selected_refs
        )

    # =====================================================
    # Evidence Natural Language Interpretation
    # =====================================================

    def interpret_evidence(
        self,
        record
    ):

        artifact = str(
            record.get(
                "artifact",
                ""
            )
        )

        # -------------------------------------------------
        # EVTX
        # -------------------------------------------------

        if artifact.startswith(
            "evtx:"
        ):

            event_id = record.get(
                "event_id"
            )

            timestamp = record.get(
                "timestamp",
                "알 수 없는 시각"
            )

            computer = record.get(
                "computer",
                "알 수 없는 시스템"
            )

            fields = record.get(
                "fields",
                {}
            )

            # Event ID 4720
            if event_id == 4720:

                target = fields.get(
                    "TargetUserName",
                    "알 수 없는 계정"
                )

                subject = fields.get(
                    "SubjectUserName",
                    "알 수 없는 주체"
                )

                return (
                    f"{timestamp}에 "
                    f"{computer} 시스템에서 "
                    f"{subject}에 의해 새로운 사용자 계정 "
                    f"'{target}'이 생성되었습니다. "
                    f"Windows Security Event ID 4720은 "
                    f"사용자 계정 생성 이벤트입니다."
                )

            # Event ID 4732
            if event_id == 4732:

                group = fields.get(
                    "TargetUserName",
                    "알 수 없는 그룹"
                )

                member = fields.get(
                    "MemberName",
                    "알 수 없는 계정"
                )

                return (
                    f"{timestamp}에 "
                    f"{computer} 시스템에서 "
                    f"'{member}' 계정이 "
                    f"'{group}' 로컬 보안 그룹에 "
                    f"추가되었습니다. "
                    f"Windows Security Event ID 4732는 "
                    f"로컬 보안 그룹 구성원 추가 이벤트입니다."
                )

            return (
                f"{timestamp}에 "
                f"{computer} 시스템에서 "
                f"Windows Event ID {event_id} 이벤트가 "
                f"기록되었습니다. "
                f"아래 핵심 필드와 원본 레코드를 확인하여 "
                f"사건과의 연관성을 판단해야 합니다."
            )

        # -------------------------------------------------
        # $MFT
        # -------------------------------------------------

        if artifact == "$MFT":

            path = record.get(
                "path",
                "알 수 없는 파일"
            )

            si_ctime = record.get(
                "si_ctime",
                "-"
            )

            fn_ctime = record.get(
                "fn_ctime",
                "-"
            )

            flags = record.get(
                "flags",
                []
            )

            if "timestamp_mismatch" in flags:

                return (
                    f"'{path}' 파일이 "
                    f"$MFT에서 확인되었습니다. "
                    f"$STANDARD_INFORMATION의 생성 시각은 "
                    f"{si_ctime}이고, "
                    f"$FILE_NAME의 생성 시각은 "
                    f"{fn_ctime}입니다. "
                    f"두 생성 시각이 일치하지 않아 "
                    f"타임스탬프 변경 또는 조작 가능성을 "
                    f"추가 검토할 필요가 있습니다."
                )

            return (
                f"'{path}' 파일의 "
                f"$MFT 레코드가 확인되었습니다. "
                f"현재 레코드에서는 "
                f"timestamp_mismatch와 같은 "
                f"특이 플래그가 확인되지 않았습니다."
            )

        return (
            "이 Evidence 유형에 대한 "
            "전용 자연어 해석 규칙은 아직 구현되지 않았습니다. "
            "아래 핵심 필드와 Raw Parsed Record를 확인하세요."
        )

    # =====================================================
    # Evidence Detail
    # =====================================================

    def show_evidence_detail(
        self,
        item
    ):

        if item is None:
            return

        ref = item.text()

        evidence = (
            self.evidence_records.get(
                ref
            )
        )

        if not evidence:

            self.evidence_detail.setPlainText(
                "Evidence 데이터를 찾을 수 없습니다."
            )

            return

        source = evidence.get(
            "source",
            "-"
        )

        record = evidence.get(
            "record",
            {}
        )

        artifact = str(
            record.get(
                "artifact",
                "-"
            )
        )

        interpretation = (
            self.interpret_evidence(
                record
            )
        )

        parts = []

        # -------------------------------------------------
        # Natural Language
        # -------------------------------------------------

        parts.append(
            "<h2>Evidence Interpretation</h2>"
        )

        parts.append(
            """
            <p>
                <b>Rule-based explanation</b>
            </p>
            """
        )

        parts.append(
            f"""
            <p>
                {html.escape(interpretation)}
            </p>
            """
        )

        parts.append(
            "<hr>"
        )

        # -------------------------------------------------
        # Evidence Info
        # -------------------------------------------------

        parts.append(
            "<h3>Evidence Information</h3>"
        )

        parts.append(
            f"""
            <p>
                <b>Reference:</b>
                {html.escape(ref)}
                <br>

                <b>Artifact:</b>
                {html.escape(artifact)}
                <br>

                <b>Source:</b>
                {html.escape(str(source))}
            </p>
            """
        )

        # -------------------------------------------------
        # EVTX Detail
        # -------------------------------------------------

        if artifact.startswith(
            "evtx:"
        ):

            event_id = record.get(
                "event_id",
                "-"
            )

            timestamp = record.get(
                "timestamp",
                "-"
            )

            computer = record.get(
                "computer",
                "-"
            )

            channel = record.get(
                "channel",
                "-"
            )

            offset = record.get(
                "offset",
                "-"
            )

            parts.append(
                "<h3>Event Information</h3>"
            )

            parts.append(
                f"""
                <p>
                    <b>Event ID:</b>
                    {html.escape(str(event_id))}
                    <br>

                    <b>Timestamp:</b>
                    {html.escape(str(timestamp))}
                    <br>

                    <b>Computer:</b>
                    {html.escape(str(computer))}
                    <br>

                    <b>Channel:</b>
                    {html.escape(str(channel))}
                    <br>

                    <b>Offset:</b>
                    {html.escape(str(offset))}
                </p>
                """
            )

            fields = record.get(
                "fields",
                {}
            )

            if fields:

                parts.append(
                    "<h3>Key Fields</h3>"
                )

                parts.append(
                    "<table cellpadding='5'>"
                )

                for key, value in (
                    fields.items()
                ):

                    parts.append(
                        f"""
                        <tr>
                            <td>
                                <b>
                                    {html.escape(str(key))}
                                </b>
                            </td>

                            <td>
                                {html.escape(str(value))}
                            </td>
                        </tr>
                        """
                    )

                parts.append(
                    "</table>"
                )

        # -------------------------------------------------
        # MFT Detail
        # -------------------------------------------------

        elif artifact == "$MFT":

            path = record.get(
                "path",
                "-"
            )

            size = record.get(
                "size",
                "-"
            )

            offset = record.get(
                "offset",
                "-"
            )

            si_ctime = record.get(
                "si_ctime",
                "-"
            )

            fn_ctime = record.get(
                "fn_ctime",
                "-"
            )

            parts.append(
                "<h3>File Information</h3>"
            )

            parts.append(
                f"""
                <p>
                    <b>Path:</b>
                    {html.escape(str(path))}
                    <br>

                    <b>Size:</b>
                    {html.escape(str(size))}
                    bytes
                    <br>

                    <b>Offset:</b>
                    {html.escape(str(offset))}
                </p>
                """
            )

            parts.append(
                "<h3>Timestamp Comparison</h3>"
            )

            parts.append(
                f"""
                <p>
                    <b>$SI CTime:</b>
                    {html.escape(str(si_ctime))}
                    <br>

                    <b>$FN CTime:</b>
                    {html.escape(str(fn_ctime))}
                </p>
                """
            )

        # -------------------------------------------------
        # Flags
        # -------------------------------------------------

        flags = record.get(
            "flags",
            []
        )

        if flags:

            parts.append(
                "<h3>Flags</h3>"
            )

            parts.append(
                "<ul>"
            )

            for flag in flags:

                parts.append(
                    f"""
                    <li>
                        {html.escape(str(flag))}
                    </li>
                    """
                )

            parts.append(
                "</ul>"
            )

        # -------------------------------------------------
        # Raw JSON
        # -------------------------------------------------

        raw_json = json.dumps(
            record,
            ensure_ascii=False,
            indent=2
        )

        parts.append(
            "<hr>"
        )

        parts.append(
            "<h3>Raw Parsed Record</h3>"
        )

        parts.append(
            "<pre>"
            + html.escape(
                raw_json
            )
            + "</pre>"
        )

        self.evidence_detail.setHtml(
            "".join(parts)
        )

    # =====================================================
    # Report
    # =====================================================

    def load_report(self):

        case_dir = self.get_case_dir()

        if case_dir is None:
            return

        report_file = (
            case_dir
            / "07_report.md"
        )

        if not report_file.exists():

            self.report_output.setPlainText(
                "07_report.md를 찾을 수 없습니다."
            )

            return

        try:

            report_text = (
                report_file.read_text(
                    encoding="utf-8"
                )
            )

            self.report_output.setMarkdown(
                report_text
            )

        except Exception as e:

            self.report_output.setPlainText(
                f"Report 로드 실패:\n{e}"
            )

    # =====================================================
    # View
    # =====================================================

    def toggle_input_panel(
        self,
        checked
    ):

        self.input_panel.setVisible(
            checked
        )

        if checked:

            self.main_splitter.setSizes([
                360,
                540
            ])

        self.statusBar().showMessage(
            (
                "Input Panel Visible"
                if checked
                else "Input Panel Hidden"
            )
        )

    def toggle_status_bar(
        self,
        checked
    ):

        self.statusBar().setVisible(
            checked
        )

    # =====================================================
    # Tools
    # =====================================================

    def open_case_folder(self):

        case_dir = self.get_case_dir()

        if case_dir is None:

            QMessageBox.information(
                self,
                "Open Case Folder",
                "Case ID가 입력되지 않았습니다."
            )

            return

        self.open_path_in_system(
            case_dir
        )

    def open_evidence_folder(self):

        evidence_dir = (
            self.evidence_input
            .text()
            .strip()
        )

        if not evidence_dir:

            QMessageBox.information(
                self,
                "Open Evidence Folder",
                "Evidence Directory가 선택되지 않았습니다."
            )

            return

        self.open_path_in_system(
            evidence_dir
        )

    # =====================================================
    # Pipeline Information
    # =====================================================

    def show_pipeline_information(self):

        QMessageBox.information(
            self,
            "8vidence Pipeline",
            (
                "<h2>8vidence Analysis Pipeline</h2>"

                "<p>"
                "<b>Stage 01 — Input</b><br>"
                "Incident 정보와 분석 입력을 준비합니다."
                "</p>"

                "<p>"
                "<b>Stage 02 — Scenario Normalize</b><br>"
                "자연어 또는 경보 정보를 "
                "분석 가능한 시나리오로 정규화합니다."
                "</p>"

                "<p>"
                "<b>Stage 03 — Artifact Selection</b><br>"
                "시나리오에 필요한 Windows "
                "Forensic Artifact를 선별합니다."
                "</p>"

                "<p>"
                "<b>Stage 04 — Artifact Parsing</b><br>"
                "선택된 Artifact를 결정론적으로 파싱합니다."
                "</p>"

                "<p>"
                "<b>Stage 05 — sLLM Interpretation</b><br>"
                "파싱된 Evidence를 기반으로 "
                "침해 정황을 해석합니다."
                "</p>"

                "<p>"
                "<b>Stage 06 — Evidence Verification</b><br>"
                "LLM Finding이 실제 Evidence와 "
                "일치하는지 검증합니다."
                "</p>"

                "<p>"
                "<b>Stage 07 — Report</b><br>"
                "검증된 결과를 DFIR Report로 생성합니다."
                "</p>"
            )
        )

    # =====================================================
    # Error
    # =====================================================

    def analysis_error(
        self,
        message
    ):

        self.log_output.append(
            f"[ERROR] {message}"
        )

        self.elapsed_timer.stop()
        self.set_analysis_controls("ERROR")
        self.update_elapsed_time()

        self.statusBar().showMessage(
            "Analysis Error"
        )

        self.tabs.setCurrentWidget(
            self.log_tab
        )

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            self.worker.request_stop()
            self.worker.wait(3000)
        event.accept()

    # =====================================================
    # About
    # =====================================================

    def show_about(self):

        QMessageBox.about(
            self,
            "About 8vidence",
            (
                "<h2>8vidence</h2>"
                "<p>"
                "<b>Evidence-driven DFIR Triage</b>"
                "</p>"

                "<p>"
                "시나리오 기반 Artifact 선별, "
                "결정론적 Forensic Parsing, "
                "sLLM 기반 Interpretation, "
                "Evidence Verification을 통해 "
                "침해사고 분석을 지원하는 "
                "DFIR Triage 도구입니다."
                "</p>"
            )
        )


# =========================================================
# Main
# =========================================================

if __name__ == "__main__":

    app = QApplication(
        sys.argv
    )

    project_root = (
        Path(__file__)
        .resolve()
        .parent
    )

    icon_path = (
        project_root
        / "assets"
        / "8vidence.ico"
    )

    if icon_path.exists():

        app.setWindowIcon(
            QIcon(str(icon_path))
        )

    window = MainWindow()

    window.show()

    sys.exit(
        app.exec()
    )