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
from open_webui.utils.rag_crypto import (
    KEYED_FIELDS,
    decrypt_result,
    encrypt_items,
    hash_token,
)
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
        *,
        key: Optional[bytes] = None,
    ) -> None:
        # Deleting by id or by a plain field needs no key. Deleting by a field
        # derived from the content does, because the stored value is keyed and
        # the caller is passing the unkeyed one.
        return self._inner.delete(
            collection_name=collection_name,
            ids=ids,
            filter=_protect_filter(filter, key, collection_name),
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
            filter=_protect_filter(filter, key, collection_name),
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
            collection_name=collection_name,
            filter=_protect_filter(filter, key, collection_name),
            limit=limit,
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


def _protect_filter(
    filter: Optional[Dict], key: Optional[bytes], collection_name: str
) -> Optional[Dict]:
    """Translate a filter written in plain values into the stored ones.

    A caller filters on the hash it computed from the document. What is stored
    is that hash keyed with the collection's key, so the filter has to be keyed
    the same way to match. Doing it here rather than at each call site means a
    caller cannot forget, and cannot accidentally write the plain hash into a
    query that would then match nothing and look like an empty collection.
    """
    if not filter:
        return filter

    keyed = [field for field in KEYED_FIELDS if field in filter]
    if not keyed:
        return filter

    if not key:
        raise VectorKeyError(
            f"Filtering collection {collection_name} on {', '.join(keyed)} needs "
            "its key: the stored value is derived from the content with it."
        )

    return {**filter, **{field: hash_token(filter[field], key) for field in keyed}}


def _check(key: bytes, collection_name: str) -> None:
    if not key:
        raise VectorKeyError(
            f"No key supplied for collection {collection_name}; refusing to touch it."
        )
