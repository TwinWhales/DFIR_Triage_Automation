"""단계 간 공용 코드.

여기와 ``schemas/``만이 단계들의 유일한 접점이다. 초기에 골격을 확정한 뒤
동결하며, 이후 변경은 전체 공지를 거친다.
"""

from . import attack, errors, io, refs, schema

__all__ = ["attack", "errors", "io", "refs", "schema"]
