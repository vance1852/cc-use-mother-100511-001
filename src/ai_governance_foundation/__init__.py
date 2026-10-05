"""科技战略协作基础服务的服务端基础包。"""

from .permissions import PermissionService
from .policy import evaluate
from .service import DomainService

__all__ = ["DomainService", "PermissionService", "evaluate"]
