from __future__ import annotations

import tkinter as tk
from tkinter import filedialog

from fastapi import APIRouter, HTTPException


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