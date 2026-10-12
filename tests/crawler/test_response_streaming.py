import asyncio

from raveneye.crawler.engine import _read_response_body


class FragmentedContent:
    """Small StreamReader stand-in that yields short network-like chunks."""

    def __init__(self, body: bytes, fragment_size: int = 113):
        self.body = body
        self.fragment_size = fragment_size
        self.offset = 0

    async def iter_chunked(self, _size: int):
        while self.offset < len(self.body):
            end = min(self.offset + self.fragment_size, len(self.body))
            chunk = self.body[self.offset:end]
            self.offset = end
            yield chunk


def test_response_reader_accumulates_fragmented_body_until_eof():
    body = b"<a href='/" + (b"x" * 400_000) + b"'>page</a>"

    read_body, truncated = asyncio.run(_read_response_body(FragmentedContent(body), 500_000))

    assert read_body == body
    assert not truncated


def test_response_reader_caps_body_and_marks_only_actual_truncation():
    exact = b"a" * 4096
    oversized = exact + b"b" * 300

    exact_body, exact_truncated = asyncio.run(_read_response_body(FragmentedContent(exact), len(exact)))
    bounded_body, bounded_truncated = asyncio.run(_read_response_body(FragmentedContent(oversized), len(exact)))

    assert exact_body == exact
    assert not exact_truncated
    assert bounded_body == exact
    assert bounded_truncated
