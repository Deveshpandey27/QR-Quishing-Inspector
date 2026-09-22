from app.api.routes.pages import router as pages_router
from app.api.routes.health import router as health_router
from app.api.routes.analysis import router as analysis_router
from app.api.routes.history import router as history_router
from app.api.routes.report import router as report_router
from app.api.routes.auth import router as auth_router

__all__ = [
    "pages_router",
    "health_router",
    "analysis_router",
    "history_router",
    "report_router",
    "auth_router",
]


