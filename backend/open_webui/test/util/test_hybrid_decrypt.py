import asyncio

from open_webui.retrieval import utils as retrieval_utils
from open_webui.retrieval.utils import VectorSearchRetriever
from open_webui.retrieval.vector.main import SearchResult
from open_webui.utils import rag_crypto
from open_webui.utils.crypto_context import set_current_user_id
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.rag_crypto import _encrypt_str


def test_hybrid_retriever_decrypts_documents(monkeypatch):
    kdek = generate_dek()
    result = SearchResult(
        ids=[["c1"]],
        documents=[[_encrypt_str("patient record is secret", kdek)]],
        metadatas=[[{"name": _encrypt_str("report.pdf", kdek)}]],
        distances=[[0.0]],
    )

    monkeypatch.setattr(
        retrieval_utils.VECTOR_DB_CLIENT, "search", lambda **kwargs: result
    )
    monkeypatch.setattr(rag_crypto, "resolve_kdek", lambda c, u, db=None: kdek)
    set_current_user_id("member-1")

    async def _embed(query, prefix=None):
        return [0.1, 0.2]

    retriever = VectorSearchRetriever(
        collection_name="kid", embedding_function=_embed, top_k=1
    )
    try:
        docs = asyncio.run(
            retriever._aget_relevant_documents("q", run_manager=None)
        )
        assert docs[0].page_content == "patient record is secret"
        assert docs[0].metadata["name"] == "report.pdf"
    finally:
        set_current_user_id(None)
