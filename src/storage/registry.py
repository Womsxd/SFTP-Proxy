from typing import Type
from src.storage.base import StorageBackend
from src.storage.disk import DiskStorage
from src.storage.s3 import S3Storage


STORAGE_REGISTRY: dict[str, Type[StorageBackend]] = {
    "disk": DiskStorage,
    "s3": S3Storage,
}


def get_storage(storage_type: str = None, config: dict = None) -> StorageBackend:
    if storage_type is None:
        from src.config import get_config
        cfg = get_config()
        storage_type = cfg.storage.get('type', 'disk')

    storage_class = STORAGE_REGISTRY.get(storage_type)
    if storage_class is None:
        raise ValueError(f"Unknown storage type: {storage_type}")

    return storage_class(config=config)


__all__ = [
    'StorageBackend',
    'DiskStorage',
    'S3Storage',
    'STORAGE_REGISTRY',
    'get_storage'
]
