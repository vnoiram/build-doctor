class FormatError(Exception):
    """解析不能な入力。reason_code は CORRUPT / UNSUPPORTED_FORMAT など。"""

    def __init__(self, reason_code: str, detail: str):
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail
