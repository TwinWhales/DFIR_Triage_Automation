from __future__ import annotations

from ui.tcl_paths import ensure_tcl_library

# tkinter 를 들이기 전에 Tcl 경로를 맞춘다. venv 에서는 이것이 없으면
# ``Tk()`` 가 ``Can't find a usable init.tcl`` 로 죽는다 — ui/tcl_paths.py.
ensure_tcl_library()

import tkinter as tk  # noqa: E402  (위 경로 설정 뒤에 와야 한다)
from tkinter import filedialog  # noqa: E402

from fastapi import APIRouter, HTTPException  # noqa: E402


router = APIRouter(
    prefix="/api/evidence",
    tags=["evidence"],
)


@router.get("/browse")
def browse_evidence():
    root = None

    try:
        root = tk.Tk()
        root.withdraw()

        # 선택창이 다른 창 뒤에 숨는 것을 방지
        root.attributes("-topmost", True)

        selected_path = filedialog.askdirectory(
            title="Evidence 폴더 선택",
        )

        if not selected_path:
            return {
                "selected": False,
                "path": None,
            }

        return {
            "selected": True,
            "path": selected_path,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"폴더 선택창을 열 수 없습니다: {exc}",
        ) from exc

    finally:
        if root is not None:
            root.destroy()

@router.get("/browse-image")
def browse_evidence_image():
    root = None

    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)

        selected_path = filedialog.askopenfilename(
            title="Evidence 디스크 이미지 선택",
            filetypes=[
                (
                    "Disk Images",
                    "*.E01 *.e01 *.dd *.raw *.img *.001",
                ),
                ("All Files", "*.*"),
            ],
        )

        if not selected_path:
            return {
                "selected": False,
                "path": None,
            }

        return {
            "selected": True,
            "path": selected_path,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"디스크 이미지 선택창을 열 수 없습니다: {exc}",
        ) from exc

    finally:
        if root is not None:
            root.destroy()