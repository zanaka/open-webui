"""The vector store, with protection applied at the boundary rather than by callers.

Chunk text and vectors are protected on the way in and restored on the way out,
so no caller has to remember to do it. Every method that touches either one takes
the collection's key as a required argument: a caller without a key cannot call
them at all, which is what stops a newly added write path from quietly storing
plaintext. Methods that only touch ids and collection names take no key.

Keys come from open_webui.utils.vector_keys.
"""

import logging
from typing import Dict, List, Optional, Union

from open_webui.retrieval.vector.main import GetResult, SearchResult, VectorItem
from open_webui.utils.rag_crypto import decrypt_result, encrypt_items
from open_webui.utils.vector_keys import VectorKeyError
from open_webui.utils.vem_crypto import rotate_items, rotate_vectors

log = logging.getLogger(__name__)


class EncryptingVectorClient:
    def __init__(self, inner):
        self._inner = inner

    # -- collection and id level: no document text or vectors involved --

    def has_collection(self, collection_name: str) -> bool:
        return self._inner.has_collection(collection_name=collection_name)

    def delete_collection(self, collection_name: str) -> None:
        return self._inner.delete_collection(collection_name=collection_name)

    def delete(
        self,
        collection_name: str,
        ids: Optional[List[str]] = None,
        filter: Optional[Dict] = None,
    ) -> None:
        return self._inner.delete(
            collection_name=collection_name, ids=ids, filter=filter
        )

    def reset(self) -> None:
        return self._inner.reset()

    # -- writes --

    def insert(
        self, collection_name: str, items: List[VectorItem], *, key: bytes
    ) -> None:
        self._protect(items, key)
        return self._inner.insert(collection_name=collection_name, items=items)

    def upsert(
        self, collection_name: str, items: List[VectorItem], *, key: bytes
    ) -> None:
        self._protect(items, key)
        return self._inner.upsert(collection_name=collection_name, items=items)

    # -- reads --

    def search(
        self,
        collection_name: str,
        vectors: List[List[Union[float, int]]],
        *,
        key: bytes,
        filter: Optional[Dict] = None,
        limit: int = 10,
    ) -> Optional[SearchResult]:
        _check(key, collection_name)
        result = self._inner.search(
            collection_name=collection_name,
            vectors=rotate_vectors(vectors, key),
            filter=filter,
            limit=limit,
        )
        return decrypt_result(result, key)

    def query(
        self,
        collection_name: str,
        filter: Dict,
        *,
        key: bytes,
        limit: Optional[int] = None,
    ) -> Optional[GetResult]:
        _check(key, collection_name)
        result = self._inner.query(
            collection_name=collection_name, filter=filter, limit=limit
        )
        return decrypt_result(result, key)

    def get(self, collection_name: str, *, key: bytes) -> Optional[GetResult]:
        _check(key, collection_name)
        return decrypt_result(self._inner.get(collection_name=collection_name), key)

    @staticmethod
    def _protect(items: List[VectorItem], key: bytes) -> None:
        _check(key, "write")
        encrypt_items(items, key)
        rotate_items(items, key)


def _check(key: bytes, collection_name: str) -> None:
    if not key:
        raise VectorKeyError(
            f"No key supplied for collection {collection_name}; refusing to touch it."
        )
