"""Quick test for conversation fingerprint logic."""
from llm_passthough_log.storage import compute_conversation_fingerprint, extract_msg_count


def test_same_conversation_same_fingerprint():
    body1 = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "你是一个助手"},
            {"role": "user", "content": "你好"},
        ],
    }
    body2 = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "你是一个助手"},
            {"role": "user", "content": "你好"},
            {"role": "assistant", "content": "你好！"},
            {"role": "user", "content": "谢谢"},
        ],
    }
    fp1 = compute_conversation_fingerprint(body1, model="gpt-4", client="192.168.1.1")
    fp2 = compute_conversation_fingerprint(body2, model="gpt-4", client="192.168.1.1")
    assert fp1 is not None
    assert fp1 == fp2, f"Expected same fingerprint, got {fp1} != {fp2}"
    assert extract_msg_count(body1) == 2
    assert extract_msg_count(body2) == 4


def test_different_system_prompt_different_fingerprint():
    body_a = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "你是助手"},
            {"role": "user", "content": "hi"},
        ],
    }
    body_b = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "你是翻译"},
            {"role": "user", "content": "hi"},
        ],
    }
    fp_a = compute_conversation_fingerprint(body_a, model="gpt-4", client="10.0.0.1")
    fp_b = compute_conversation_fingerprint(body_b, model="gpt-4", client="10.0.0.1")
    assert fp_a != fp_b


def test_no_messages_returns_none():
    body = {"model": "gpt-4", "prompt": "hello"}
    assert compute_conversation_fingerprint(body, model="gpt-4", client="1.1.1.1") is None
    assert extract_msg_count(body) == 0


def test_no_system_prompt_still_works():
    body = {
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "hello"},
        ],
    }
    fp = compute_conversation_fingerprint(body, model="gpt-4", client="10.0.0.1")
    assert fp is not None
    assert len(fp) == 12
