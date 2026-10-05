"""人工智能治理协作基础服务的服务端基础包。"""

from .permissions import PermissionService
from .service import DomainService

__all__ = ["DomainService", "PermissionService"]
