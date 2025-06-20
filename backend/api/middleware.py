"""
API中间件配置
"""

import time
import uuid
from typing import Callable, Dict, List
from fastapi import Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import logging

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """请求日志中间件"""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # 生成请求ID
        request_id = str(uuid.uuid4())

        # 记录请求开始
        start_time = time.time()
        logger.info(
            "Request started",
            extra={
                "request_id": request_id,
                "method": request.method,
                "url": str(request.url),
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            },
        )

        # 将请求ID添加到请求状态
        request.state.request_id = request_id

        try:
            # 执行请求
            response = await call_next(request)

            # 记录请求完成
            process_time = time.time() - start_time
            logger.info(
                "Request completed",
                extra={
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "process_time": f"{process_time:.3f}s",
                },
            )

            # 添加响应头
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = f"{process_time:.3f}s"

            return response

        except Exception as e:
            # 记录请求错误
            process_time = time.time() - start_time
            logger.error(
                "Request failed",
                extra={
                    "request_id": request_id,
                    "error": str(e),
                    "process_time": f"{process_time:.3f}s",
                },
            )
            raise


class RateLimitMiddleware(BaseHTTPMiddleware):
    """简单的速率限制中间件"""

    def __init__(self, app, calls: int = 100, period: int = 60):
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.clients: dict = {}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()

        # 清理过期记录
        if client_ip in self.clients:
            self.clients[client_ip] = [
                timestamp
                for timestamp in self.clients[client_ip]
                if current_time - timestamp < self.period
            ]
        else:
            self.clients[client_ip] = []

        # 检查速率限制
        if len(self.clients[client_ip]) >= self.calls:
            raise HTTPException(
                status_code=429, detail="Too many requests. Please try again later."
            )

        # 记录当前请求
        self.clients[client_ip].append(current_time)

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """安全头中间件"""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # 添加安全头
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        return response


def setup_middleware(app):
    """设置所有中间件"""

    # CORS中间件
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # 生产环境应该限制具体域名
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Gzip压缩中间件
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # 自定义中间件
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    # app.add_middleware(RateLimitMiddleware, calls=100, period=60)  # 可选启用

    logger.info("Middleware setup completed")
