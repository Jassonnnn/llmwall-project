from typing import Any, Dict, Optional


class AppError(Exception):
    def __init__(
        self,
        *,
        code: str,
        message: str,
        status_code: int = 400,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}


def error_payload(
    *,
    code: str,
    message: str,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "status": "error",
        "code": code,
        "message": message,
        "details": details or {},
    }
