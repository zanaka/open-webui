import asyncio

from open_webui.retrieval import utils as retrieval_utils
from open_webui.retrieval.utils import VectorSearchRetriever
from open_webui.retrieval.vector.main import SearchResult
from open_webui.utils.crypto_utils import generate_dek
from open_webui.utils.rag_crypto import _encrypt_str


def test_hybrid_retriever_returns_readable_documents(monkeypatch):
    """The retriever feeding BM25 must hand it text, not ciphertext (#67)."""
    key = generate_dek()
    stored = SearchResult(
        ids=[["c1"]],
        documents=[[_encrypt_str("patient record is secret", key)]],
        metadatas=[[{"name": _encrypt_str("report.pdf", key)}]],
        distances=[[0.0]],
    )

    monkeypatch.setattr(
        retrieval_utils.VECTOR_DB_CLIENT._inner,
        "search",
        lambda **kwargs: stored,
    )

    async def _embed(query, prefix=None):
        return [0.1, 0.2]

    retriever = VectorSearchRetriever(
        collection_name="kid",
        collection_key=key,
        embedding_function=_embed,
        top_k=1,
    )

    docs = asyncio.run(retriever._aget_relevant_documents("q", run_manager=None))

    assert docs[0].page_content == "patient record is secret"
    assert docs[0].metadata["name"] == "report.pdf"
