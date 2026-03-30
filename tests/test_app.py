import gzip
import json
import sqlite3

import httpx
from fastapi.testclient import TestClient

from llm_passthough_log import app as app_module
from llm_passthough_log.app import create_app
from llm_passthough_log.config import Settings
from llm_passthough_log.storage import LogStore


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin-pass"


def build_settings(tmp_path):
    return Settings(
        app_name="test-app",
        downstream_url="https://provider.test",
        log_dir=tmp_path,
        jsonl_path=tmp_path / "logs.jsonl",
        sqlite_path=tmp_path / "logs.db",
        request_timeout_seconds=30.0,
        admin_title="Test Console",
        provider_routes={},
        queue_maxsize=16,
        admin_page_size_default=20,
        admin_page_size_max=100,
        default_provider_name="provider.test",
        admin_username=ADMIN_USERNAME,
        admin_password=ADMIN_PASSWORD,
    )


def login_admin(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/admin/api/login",
        json={"name": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )
    assert response.status_code == 200
    return {"X-Session-Token": response.json()["session_token"]}


def login_user(client: TestClient, name: str, password: str) -> dict[str, str]:
    response = client.post(
        "/admin/api/login",
        json={"name": name, "password": password},
    )
    assert response.status_code == 200
    return {"X-Session-Token": response.json()["session_token"]}


def test_proxy_logs_non_stream_request(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"id": "resp_1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
        )

    transport = httpx.MockTransport(handler)
    app = create_app(build_settings(tmp_path), downstream_transport=transport)

    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-test",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
        assert response.status_code == 200
        assert response.json()["choices"][0]["message"]["content"] == "ok"

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        logs = client.get("/admin/api/logs", headers=admin_headers).json()
        assert logs["pagination"]["total"] == 1
        assert logs["items"][0]["request_model"] == "gpt-test"
        detail = client.get(f"/admin/api/logs/{logs['items'][0]['id']}", headers=admin_headers).json()
        assert detail["response_status"] == 200
        assert detail["request_body"]["messages"][0]["content"] == "hello"


def test_admin_log_detail_masks_sensitive_values(tmp_path):
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"id": "resp_1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
        )

    transport = httpx.MockTransport(handler)
    app = create_app(build_settings(tmp_path), downstream_transport=transport)

    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-test",
                "api_key": "sk-inline-body-secret-12345678",
                "messages": [{"role": "user", "content": "authorization Bearer sk-request-secret-987654321"}],
            },
            headers={"Authorization": "Bearer sk-header-secret-1234567890"},
        )
        assert response.status_code == 200

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        logs = client.get("/admin/api/logs", headers=admin_headers).json()
        detail = client.get(f"/admin/api/logs/{logs['items'][0]['id']}", headers=admin_headers)
        assert detail.status_code == 200
        payload = detail.json()
        raw = json.dumps(payload, ensure_ascii=False)
        assert "sk-header-secret-1234567890" not in raw
        assert "sk-inline-body-secret-12345678" not in raw
        assert "sk-request-secret-987654321" not in raw
        assert payload["request_headers"]["authorization"].startswith("Bearer ")
        assert "..." in payload["request_headers"]["authorization"]
        assert payload["request_body"]["api_key"] != "sk-inline-body-secret-12345678"


def test_admin_logs_list_masks_preview_sensitive_values(tmp_path):
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"id": "resp_1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
        )

    app = create_app(build_settings(tmp_path), downstream_transport=httpx.MockTransport(handler))

    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-test",
                "messages": [{"role": "user", "content": "authorization Bearer sk-preview-secret-12345678"}],
            },
        )
        assert response.status_code == 200

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        logs = client.get("/admin/api/logs", headers=admin_headers)
        assert logs.status_code == 200
        payload = logs.json()
        preview = payload["items"][0]["preview"]
        assert "sk-preview-secret-12345678" not in preview
        assert "Bearer sk-" not in preview
        assert "..." in preview


def test_storage_entry_json_masks_sensitive_values(tmp_path):
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"id": "resp_1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
        )

    app = create_app(build_settings(tmp_path), downstream_transport=httpx.MockTransport(handler))

    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-test",
                "api_key": "sk-store-body-secret-12345678",
                "messages": [{"role": "user", "content": "authorization Bearer sk-store-msg-secret-12345678"}],
            },
            headers={"Authorization": "Bearer sk-store-header-secret-12345678"},
        )
        assert response.status_code == 200

    with sqlite3.connect(tmp_path / "logs.db") as conn:
        row = conn.execute("SELECT entry_json, preview FROM logs ORDER BY created_at DESC LIMIT 1").fetchone()
        assert row is not None
        entry_json, preview = row

    assert "sk-store-body-secret-12345678" not in entry_json
    assert "sk-store-msg-secret-12345678" not in entry_json
    assert "sk-store-header-secret-12345678" not in entry_json
    assert "Bearer sk-" not in entry_json
    assert "Bearer sk-" not in preview


def test_proxy_supports_sse_passthrough(tmp_path):
    def handler(_: httpx.Request) -> httpx.Response:
        body = b"data: {\"delta\":\"hello\"}\n\ndata: [DONE]\n\n"
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=body,
        )

    transport = httpx.MockTransport(handler)
    app = create_app(build_settings(tmp_path), downstream_transport=transport)

    with TestClient(app) as client:
        response = client.post("/v1/stream", json={"stream": True})
        assert response.status_code == 200
        assert "data: [DONE]" in response.text

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        logs = client.get("/admin/api/logs", headers=admin_headers).json()
        assert logs["pagination"]["total"] == 1
        detail = client.get(f"/admin/api/logs/{logs['items'][0]['id']}", headers=admin_headers).json()
        assert detail["response_body"].startswith("data: {\"delta\":\"hello\"}")


def test_proxy_forces_stream_include_usage(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8"))
        assert payload["stream"] is True
        assert payload["stream_options"]["include_usage"] is True
        body = b"data: {\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\ndata: [DONE]\n\n"
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=body,
        )

    transport = httpx.MockTransport(handler)
    app = create_app(build_settings(tmp_path), downstream_transport=transport)

    with TestClient(app) as client:
        response = client.post("/v1/stream", json={"stream": True, "messages": [{"role": "user", "content": "hello"}]})
        assert response.status_code == 200
        assert "total_tokens" in response.text


def test_preconsumed_response_drops_content_encoding_header(tmp_path):
    def handler(_: httpx.Request) -> httpx.Response:
        response = httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
            },
            content=gzip.compress(b'{"ok": true}'),
        )
        response.read()
        return response

    transport = httpx.MockTransport(handler)
    app = create_app(build_settings(tmp_path), downstream_transport=transport)

    with TestClient(app) as client:
        response = client.get("/v1/test")
        assert response.status_code == 200
        assert response.json() == {"ok": True}
        assert "content-encoding" not in response.headers


def test_log_worker_survives_single_write_failure(tmp_path, monkeypatch):
    calls = {"count": 0}
    original_prepare = LogStore._prepare_entry

    def flaky_prepare(self, entry):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("temporary write failure")
        return original_prepare(self, entry)

    monkeypatch.setattr(LogStore, "_prepare_entry", flaky_prepare)

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"ok": True})

    app = create_app(build_settings(tmp_path), downstream_transport=httpx.MockTransport(handler))

    with TestClient(app) as client:
        first = client.post("/v1/test", json={"model": "first"})
        second = client.post("/v1/test", json={"model": "second"})
        assert first.status_code == 200
        assert second.status_code == 200

    error_log = tmp_path / "log-writer-errors.log"
    assert error_log.exists()

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        logs = client.get("/admin/api/logs", headers=admin_headers).json()
        assert logs["pagination"]["total"] == 1
        assert logs["items"][0]["request_model"] == "second"


def test_admin_favicon_does_not_hit_proxy(tmp_path):
    calls = {"count": 0}

    def handler(_: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"ok": True})

    app = create_app(build_settings(tmp_path), downstream_transport=httpx.MockTransport(handler))

    with TestClient(app) as client:
        response = client.get("/favicon.ico")
        assert response.status_code == 204

    assert calls["count"] == 0


def test_runtime_disables_http2_when_h2_missing(tmp_path, monkeypatch):
    captured = {"http2": None}

    class DummyTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"path": request.url.path},
            )

    def fake_async_http_transport(*, retries: int, http2: bool, **kwargs):
        captured["http2"] = http2
        assert retries == 1
        return DummyTransport()

    monkeypatch.setattr(app_module, "is_http2_available", lambda: False)
    monkeypatch.setattr(app_module.httpx, "AsyncHTTPTransport", fake_async_http_transport)

    app = app_module.create_app(build_settings(tmp_path))

    with TestClient(app) as client:
        response = client.get("/v1/test")
        assert response.status_code == 200
        assert response.json() == {"path": "/v1/test"}

    assert captured["http2"] is False


# ════════════════ 用户管理 CRUD ════════════════


def test_user_crud_lifecycle(tmp_path):
    """创建 → 列表 → 更新 → 禁用 → 删除 全流程"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        # 创建用户
        resp = client.post("/admin/api/users", json={"name": "测试用户", "password": "test-password-001"}, headers=admin_headers)
        assert resp.status_code == 200
        user = resp.json()
        uid = user["id"]
        assert user["name"] == "测试用户"
        assert user["role"] == "user"

        # 列表
        resp = client.get("/admin/api/users", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["pagination"]["total"] == 1
        assert data["items"][0]["name"] == "测试用户"

        # 按名称搜索
        resp = client.get("/admin/api/users?q=测试", headers=admin_headers)
        assert resp.json()["pagination"]["total"] == 1
        resp = client.get("/admin/api/users?q=不存在", headers=admin_headers)
        assert resp.json()["pagination"]["total"] == 0

        # 获取详情
        resp = client.get(f"/admin/api/users/{uid}", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "测试用户"

        # 更新
        resp = client.put(f"/admin/api/users/{uid}", json={"name": "改名了"}, headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "改名了"

        # 删除
        resp = client.delete(f"/admin/api/users/{uid}", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

        # 确认已删除
        resp = client.get(f"/admin/api/users/{uid}", headers=admin_headers)
        assert resp.status_code == 404


def test_user_create_requires_password(tmp_path):
    """创建用户时必须提供密码"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        resp = client.post("/admin/api/users", json={"name": "缺少密码"}, headers=admin_headers)
        assert resp.status_code == 422


def test_user_create_requires_name(tmp_path):
    """name 为空时返回 422"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        resp = client.post("/admin/api/users", json={"name": "", "password": "abc123456"}, headers=admin_headers)
        assert resp.status_code == 422


def test_proxy_uses_user_downstream_override(tmp_path):
    """用户绑定了自定义 downstream 时，代理请求应发往用户配置的目标"""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization", "")
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"ok": True})

    transport = httpx.MockTransport(handler)
    app = create_app(build_settings(tmp_path), downstream_transport=transport)

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        # 先创建一个带自定义 downstream 的用户
        resp = client.post("/admin/api/users", json={
            "name": "custom-user",
            "password": "custom-password",
            "api_key": "sk-custom-user-key",
            "downstream_url": "https://custom.api.test",
            "downstream_apikey": "sk-real-provider-key",
        }, headers=admin_headers)
        assert resp.status_code == 200

        # 使用该用户的 API Key 发起代理请求
        resp = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]},
            headers={"Authorization": "Bearer sk-custom-user-key"},
        )
        assert resp.status_code == 200

    assert "custom.api.test" in captured["url"]
    assert captured["auth"] == "Bearer sk-real-provider-key"


# ════════════════ Provider CRUD ════════════════


def test_provider_crud_lifecycle(tmp_path):
    """Provider 创建 → 列表 → 更新 → 删除 全流程"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        # 创建 provider
        resp = client.post("/admin/api/providers", json={
            "name": "OpenAI",
            "prefix_path": "openai",
            "downstream_url": "https://api.openai.com",
            "input_price": 2.5,
            "output_price": 10.0,
        }, headers=admin_headers)
        assert resp.status_code == 200
        prov = resp.json()
        pid = prov["id"]
        assert prov["name"] == "OpenAI"
        assert prov["prefix_path"] == "openai"

        # 列表
        resp = client.get("/admin/api/providers", headers=admin_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["name"] == "OpenAI"

        # 获取详情
        resp = client.get(f"/admin/api/providers/{pid}", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["input_price"] == 2.5

        # 更新
        resp = client.put(f"/admin/api/providers/{pid}", json={"name": "OpenAI Updated", "output_price": 15.0}, headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "OpenAI Updated"
        assert resp.json()["output_price"] == 15.0

        # 删除
        resp = client.delete(f"/admin/api/providers/{pid}", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

        # 确认已删除
        resp = client.get(f"/admin/api/providers/{pid}", headers=admin_headers)
        assert resp.status_code == 404


def test_provider_api_masks_downstream_apikey_for_web(tmp_path):
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        secret = "sk-provider-secret-1234567890"
        resp = client.post(
            "/admin/api/providers",
            json={
                "name": "Secret Provider",
                "prefix_path": "secret",
                "downstream_url": "https://api.example.com",
                "downstream_apikey": secret,
            },
            headers=admin_headers,
        )
        assert resp.status_code == 200
        created = resp.json()
        assert created["has_downstream_apikey"] is True
        assert created["downstream_apikey_masked"] != secret
        assert secret not in json.dumps(created, ensure_ascii=False)

        provider_id = created["id"]
        detail = client.get(f"/admin/api/providers/{provider_id}", headers=admin_headers)
        assert detail.status_code == 200
        assert secret not in json.dumps(detail.json(), ensure_ascii=False)

        listing = client.get("/admin/api/providers", headers=admin_headers)
        assert listing.status_code == 200
        assert secret not in json.dumps(listing.json(), ensure_ascii=False)

        session_data = client.get("/admin/api/session", headers=admin_headers)
        assert session_data.status_code == 200
        assert secret not in json.dumps(session_data.json(), ensure_ascii=False)


def test_log_entry_masks_url_host(tmp_path):
    """url 字段中的下游域名应被脱敏"""
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"id": "resp_1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
        )

    app = create_app(build_settings(tmp_path), downstream_transport=httpx.MockTransport(handler))

    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert resp.status_code == 200

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        logs = client.get("/admin/api/logs", headers=admin_headers).json()
        detail = client.get(f"/admin/api/logs/{logs['items'][0]['id']}", headers=admin_headers).json()
        # url 字段的主机名应被脱敏（provider.test → pro***est）
        assert "provider.test" not in detail["url"]
        assert "***" in detail["url"]
        # 路径应保留
        assert "/v1/chat/completions" in detail["url"]

    # 持久化层也应脱敏
    import sqlite3
    with sqlite3.connect(tmp_path / "logs.db") as conn:
        row = conn.execute("SELECT entry_json FROM logs ORDER BY created_at DESC LIMIT 1").fetchone()
        assert row is not None
        entry_data = json.loads(row[0])
        # url 字段中的域名应被脱敏
        assert "provider.test" not in entry_data["url"]


def test_provider_downstream_url_masked_in_web(tmp_path):
    """Provider 的 downstream_url 在 Web API 中应脱敏"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )
    downstream = "https://llm.internal-secret.example.com:30006"

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        resp = client.post(
            "/admin/api/providers",
            json={
                "name": "URL Test",
                "prefix_path": "urltest",
                "downstream_url": downstream,
            },
            headers=admin_headers,
        )
        assert resp.status_code == 200
        created = resp.json()
        # 完整域名不应出现
        assert "llm.internal-secret.example.com" not in created["downstream_url"]
        assert "***" in created["downstream_url"]
        # scheme 和 port 应保留
        assert created["downstream_url"].startswith("https://")
        assert ":30006" in created["downstream_url"]

        # 列表接口也脱敏
        listing = client.get("/admin/api/providers", headers=admin_headers).json()
        for p in listing["items"]:
            if p["id"] == created["id"]:
                assert "llm.internal-secret.example.com" not in p["downstream_url"]
                break

        # settings 接口也脱敏
        settings_resp = client.get("/admin/api/settings", headers=admin_headers).json()
        if "downstream_url" in settings_resp:
            assert "provider.test" not in settings_resp["downstream_url"]


def test_mask_url_host_function():
    """mask_url_host 单元测试"""
    from llm_passthough_log.app import mask_url_host

    # 长域名：保留前3后3
    assert mask_url_host("https://llm.snow13.top:30006/v1/chat") == "https://llm***top:30006/v1/chat"
    # 短域名 <=4：全部替换
    assert mask_url_host("http://a.co/path") == "http://****/path"
    # 中等域名 5-8
    assert mask_url_host("https://ab.co.io/api") == "https://a***o/api"
    # 无路径
    assert mask_url_host("https://api.example.com") == "https://api***com"
    # 非 URL 不变
    assert mask_url_host("just plain text") == "just plain text"
    # 空字符串
    assert mask_url_host("") == ""


def test_auth_required_when_admin_key_set(tmp_path):
    """系统必须先登录才能访问后台接口"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        # 无 session 应 401
        resp = client.get("/admin/api/overview")
        assert resp.status_code == 401

        # 错误 session 也应 401
        resp = client.get("/admin/api/overview", headers={"X-Session-Token": "wrong-token"})
        assert resp.status_code == 401

        # 正确账号密码登录后应 200
        admin_headers = login_admin(client)
        resp = client.get("/admin/api/overview", headers=admin_headers)
        assert resp.status_code == 200


def test_user_role_sees_filtered_data(tmp_path):
    """user 角色只能看到自己有权限的 provider 的数据"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        admin_hdr = login_admin(client)
        # 创建 provider
        resp = client.post("/admin/api/providers", json={
            "name": "TestProv",
            "prefix_path": "testprov",
            "downstream_url": "https://test.api",
        }, headers=admin_hdr)
        assert resp.status_code == 200
        prov_id = resp.json()["id"]

        # 创建 user 角色用户并绑定 provider
        resp = client.post("/admin/api/users", json={
            "name": "viewer",
            "password": "viewer-password",
            "provider_ids": [prov_id],
        }, headers=admin_hdr)
        assert resp.status_code == 200
        user_hdr = login_user(client, "viewer", "viewer-password")

        # user 角色不能管理 providers
        resp = client.get("/admin/api/providers", headers=user_hdr)
        assert resp.status_code == 403

        # user 角色不能管理 users
        resp = client.get("/admin/api/users", headers=user_hdr)
        assert resp.status_code == 403

        # user 可以查看 overview 和 logs
        resp = client.get("/admin/api/overview", headers=user_hdr)
        assert resp.status_code == 200

        resp = client.get("/admin/api/logs", headers=user_hdr)
        assert resp.status_code == 200


def test_session_returns_user_info(tmp_path):
    """session 端点返回用户信息和角色"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        admin_headers = login_admin(client)
        resp = client.get("/admin/api/session", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["user"]["role"] == "admin"

        # 无 key
        resp = client.get("/admin/api/session")
        assert resp.status_code == 401


def test_password_login_flow(tmp_path):
    """用户名+密码登录流程"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        admin_hdr = login_admin(client)
        # 创建带密码的用户
        resp = client.post("/admin/api/users", json={
            "name": "testuser",
            "password": "mypassword123",
        }, headers=admin_hdr)
        assert resp.status_code == 200
        user = resp.json()
        assert user["name"] == "testuser"

        # 用户名+密码登录
        resp = client.post("/admin/api/login", json={
            "name": "testuser",
            "password": "mypassword123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["user"]["name"] == "testuser"
        assert data["user"]["role"] == "user"
        assert "session_token" in data

        # 用返回的 session token 访问 session
        resp = client.get("/admin/api/session", headers={"X-Session-Token": data["session_token"]})
        assert resp.status_code == 200
        assert resp.json()["user"]["name"] == "testuser"

        # 错误密码
        resp = client.post("/admin/api/login", json={
            "name": "testuser",
            "password": "wrongpassword",
        })
        assert resp.status_code == 401

        # 修改密码
        resp = client.put(f"/admin/api/users/{user['id']}", json={
            "password": "newpassword456",
        }, headers=admin_hdr)
        assert resp.status_code == 200

        # 旧密码失败
        resp = client.post("/admin/api/login", json={
            "name": "testuser",
            "password": "mypassword123",
        })
        assert resp.status_code == 401

        # 新密码成功
        resp = client.post("/admin/api/login", json={
            "name": "testuser",
            "password": "newpassword456",
        })
        assert resp.status_code == 200


# ════════════════ Search API Tests ════════════════


def _make_app_with_logged_request(tmp_path, api_key="sk-test-search-001", model="gpt-test", user_msg="hello"):
    """Helper: create app, proxy one request with given key, return (app, key_hash)."""
    from llm_passthough_log.storage import hash_api_key

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"id": "resp_1", "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                  "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}},
        )

    app = create_app(build_settings(tmp_path), downstream_transport=httpx.MockTransport(handler))
    with TestClient(app) as client:
        resp = client.post(
            "/v1/chat/completions",
            json={"model": model, "messages": [{"role": "user", "content": user_msg}]},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200
    return app, hash_api_key(api_key)


def test_search_verify_keys_with_hashes(tmp_path):
    """verify-keys 接收 key_hashes 应返回匹配的记录数"""
    app, key_hash = _make_app_with_logged_request(tmp_path)
    with TestClient(app) as client:
        resp = client.post("/search/api/verify-keys", json={"key_hashes": [key_hash]})
        assert resp.status_code == 200
        data = resp.json()
        assert key_hash in data["keys"]
        assert data["keys"][key_hash]["count"] >= 1


def test_search_verify_keys_with_raw_keys(tmp_path):
    """verify-keys 接收原始 key 应自动 hash 后匹配"""
    raw_key = "sk-test-raw-verify"
    app, key_hash = _make_app_with_logged_request(tmp_path, api_key=raw_key)
    with TestClient(app) as client:
        resp = client.post("/search/api/verify-keys", json={"keys": [raw_key]})
        assert resp.status_code == 200
        data = resp.json()
        assert key_hash in data["keys"]
        assert data["keys"][key_hash]["count"] >= 1


def test_search_verify_keys_no_keys_returns_422(tmp_path):
    """verify-keys 不提供任何 key 应返回 422"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )
    with TestClient(app) as client:
        resp = client.post("/search/api/verify-keys", json={"key_hashes": []})
        assert resp.status_code == 422

        resp = client.post("/search/api/verify-keys", json={})
        assert resp.status_code == 422


def test_search_verify_keys_invalid_hash_ignored(tmp_path):
    """无效的 hash 格式应被忽略，有效的正常返回"""
    app, key_hash = _make_app_with_logged_request(tmp_path)
    with TestClient(app) as client:
        resp = client.post("/search/api/verify-keys", json={"key_hashes": ["not-a-valid-hash", key_hash]})
        assert resp.status_code == 200
        data = resp.json()
        assert key_hash in data["keys"]
        assert "not-a-valid-hash" not in data["keys"]


def test_search_logs_with_key_hashes(tmp_path):
    """search/api/logs 通过 key_hashes 检索日志"""
    app, key_hash = _make_app_with_logged_request(tmp_path)
    with TestClient(app) as client:
        resp = client.post("/search/api/logs", json={"key_hashes": [key_hash]})
        assert resp.status_code == 200
        data = resp.json()
        assert data["pagination"]["total"] >= 1
        assert data["items"][0]["request_model"] == "gpt-test"


def test_search_logs_with_raw_keys(tmp_path):
    """search/api/logs 通过原始 key 检索日志"""
    raw_key = "sk-test-raw-search"
    app, _ = _make_app_with_logged_request(tmp_path, api_key=raw_key)
    with TestClient(app) as client:
        resp = client.post("/search/api/logs", json={"keys": [raw_key]})
        assert resp.status_code == 200
        assert resp.json()["pagination"]["total"] >= 1


def test_search_logs_no_keys_returns_422(tmp_path):
    """search/api/logs 不提供 key 应 422"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )
    with TestClient(app) as client:
        resp = client.post("/search/api/logs", json={})
        assert resp.status_code == 422


def test_search_logs_wrong_key_returns_empty(tmp_path):
    """使用错误的 key 检索不到任何记录"""
    from llm_passthough_log.storage import hash_api_key
    app, _ = _make_app_with_logged_request(tmp_path, api_key="sk-correct-key")
    wrong_hash = hash_api_key("sk-wrong-key")
    with TestClient(app) as client:
        resp = client.post("/search/api/logs", json={"key_hashes": [wrong_hash]})
        assert resp.status_code == 200
        assert resp.json()["pagination"]["total"] == 0


def test_search_logs_path_restriction(tmp_path):
    """search API 限制 path 只能是 chat/completions 或 embeddings"""
    app, key_hash = _make_app_with_logged_request(tmp_path)
    with TestClient(app) as client:
        resp = client.post("/search/api/logs", json={
            "key_hashes": [key_hash],
            "path_contains": "admin/secret",
        })
        assert resp.status_code == 200
        # 非法 path 被重置，仍能查到 chat/completions 的记录
        assert resp.json()["pagination"]["total"] >= 1


def test_search_log_detail_with_valid_key(tmp_path):
    """search/api/logs/{id} 用正确的 key 可以查看详情"""
    app, key_hash = _make_app_with_logged_request(tmp_path)
    with TestClient(app) as client:
        logs = client.post("/search/api/logs", json={"key_hashes": [key_hash]}).json()
        log_id = logs["items"][0]["id"]
        resp = client.post(f"/search/api/logs/{log_id}", json={"key_hashes": [key_hash]})
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["response_status"] == 200


def test_search_log_detail_wrong_key_returns_404(tmp_path):
    """search/api/logs/{id} 用错误 key 应返回 404"""
    from llm_passthough_log.storage import hash_api_key
    app, key_hash = _make_app_with_logged_request(tmp_path)
    with TestClient(app) as client:
        logs = client.post("/search/api/logs", json={"key_hashes": [key_hash]}).json()
        log_id = logs["items"][0]["id"]
        wrong_hash = hash_api_key("sk-intruder-key")
        resp = client.post(f"/search/api/logs/{log_id}", json={"key_hashes": [wrong_hash]})
        assert resp.status_code == 404


def test_search_log_detail_no_keys_returns_422(tmp_path):
    """search/api/logs/{id} 不提供 key 应 422"""
    app, key_hash = _make_app_with_logged_request(tmp_path)
    with TestClient(app) as client:
        logs = client.post("/search/api/logs", json={"key_hashes": [key_hash]}).json()
        log_id = logs["items"][0]["id"]
        resp = client.post(f"/search/api/logs/{log_id}", json={})
        assert resp.status_code == 422


def test_search_conversation_timeline(tmp_path):
    """search/api/conversation/{fp} 通过 key 获取会话时间线"""
    app, key_hash = _make_app_with_logged_request(tmp_path)
    with TestClient(app) as client:
        logs = client.post("/search/api/logs", json={"key_hashes": [key_hash]}).json()
        item = logs["items"][0]
        fp = item.get("conv_fingerprint")
        if fp:
            resp = client.post(f"/search/api/conversation/{fp}", json={"key_hashes": [key_hash]})
            assert resp.status_code == 200
            data = resp.json()
            assert "items" in data
            assert len(data["items"]) >= 1


def test_search_conversation_wrong_key_empty(tmp_path):
    """search/api/conversation/{fp} 用错误 key 应返回空列表"""
    from llm_passthough_log.storage import hash_api_key
    app, key_hash = _make_app_with_logged_request(tmp_path)
    with TestClient(app) as client:
        logs = client.post("/search/api/logs", json={"key_hashes": [key_hash]}).json()
        item = logs["items"][0]
        fp = item.get("conv_fingerprint")
        if fp:
            wrong_hash = hash_api_key("sk-intruder-key")
            resp = client.post(f"/search/api/conversation/{fp}", json={"key_hashes": [wrong_hash]})
            assert resp.status_code == 200
            assert len(resp.json()["items"]) == 0


# ════════════════ _extract_search_hashes Unit Tests ════════════════


def test_extract_search_hashes_mixed():
    """同时提供 keys 和 key_hashes 应合并去重"""
    from llm_passthough_log.app import _extract_search_hashes
    from llm_passthough_log.storage import hash_api_key

    raw_key = "sk-test-mixed"
    expected_hash = hash_api_key(raw_key)

    result = _extract_search_hashes({
        "keys": [raw_key],
        "key_hashes": [expected_hash],
    })
    assert result == [expected_hash]


def test_extract_search_hashes_empty():
    """空输入应返回空列表"""
    from llm_passthough_log.app import _extract_search_hashes
    assert _extract_search_hashes({}) == []
    assert _extract_search_hashes({"keys": [], "key_hashes": []}) == []


def test_extract_search_hashes_filters_invalid():
    """无效的 hash 格式应被过滤"""
    from llm_passthough_log.app import _extract_search_hashes
    valid_hash = "a" * 64
    result = _extract_search_hashes({
        "key_hashes": ["short", "ZZZZ" * 16, valid_hash, ""],
    })
    assert result == [valid_hash]


def test_extract_search_hashes_whitespace_keys():
    """空白字符的 key 应被过滤"""
    from llm_passthough_log.app import _extract_search_hashes
    result = _extract_search_hashes({"keys": ["", "  ", "valid-key"]})
    assert len(result) == 1


# ════════════════ Admin Log Filters ════════════════


def test_admin_logs_filter_by_model(tmp_path):
    """admin 日志筛选：按 model 精确筛选"""
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"},
                              json={"id": "r1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    app = create_app(build_settings(tmp_path), downstream_transport=httpx.MockTransport(handler))
    with TestClient(app) as client:
        client.post("/v1/chat/completions", json={"model": "gpt-4", "messages": [{"role": "user", "content": "a"}]})
        client.post("/v1/chat/completions", json={"model": "claude-3", "messages": [{"role": "user", "content": "b"}]})

    with TestClient(app) as client:
        h = login_admin(client)
        all_logs = client.get("/admin/api/logs", headers=h).json()
        assert all_logs["pagination"]["total"] == 2

        gpt = client.get("/admin/api/logs?model=gpt-4", headers=h).json()
        assert gpt["pagination"]["total"] == 1
        assert gpt["items"][0]["request_model"] == "gpt-4"

        none_resp = client.get("/admin/api/logs?model=nonexistent", headers=h).json()
        assert none_resp["pagination"]["total"] == 0


def test_admin_logs_filter_by_conv_fingerprint(tmp_path):
    """admin 日志筛选：按 conv_fingerprint"""
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"},
                              json={"id": "r1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    app = create_app(build_settings(tmp_path), downstream_transport=httpx.MockTransport(handler))
    with TestClient(app) as client:
        client.post("/v1/chat/completions", json={
            "model": "gpt-4",
            "messages": [{"role": "system", "content": "sys-a"}, {"role": "user", "content": "hi"}],
        })
        client.post("/v1/chat/completions", json={
            "model": "gpt-4",
            "messages": [{"role": "system", "content": "sys-b"}, {"role": "user", "content": "hi"}],
        })

    with TestClient(app) as client:
        h = login_admin(client)
        all_logs = client.get("/admin/api/logs", headers=h).json()
        assert all_logs["pagination"]["total"] == 2

        fp0 = all_logs["items"][0]["conv_fingerprint"]
        fp1 = all_logs["items"][1]["conv_fingerprint"]
        assert fp0 != fp1

        filtered = client.get(f"/admin/api/logs?conv_fingerprint={fp0}", headers=h).json()
        assert filtered["pagination"]["total"] == 1
        assert filtered["items"][0]["conv_fingerprint"] == fp0


def test_search_logs_filter_by_conv_fingerprint(tmp_path):
    """search API 日志筛选：按 conv_fingerprint"""
    raw_key = "sk-fp-test-key"
    from llm_passthough_log.storage import hash_api_key

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"},
                              json={"id": "r1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    app = create_app(build_settings(tmp_path), downstream_transport=httpx.MockTransport(handler))
    key_hash = hash_api_key(raw_key)

    with TestClient(app) as client:
        client.post("/v1/chat/completions", json={
            "model": "gpt-4", "messages": [{"role": "system", "content": "a"}, {"role": "user", "content": "hi"}],
        }, headers={"Authorization": f"Bearer {raw_key}"})
        client.post("/v1/chat/completions", json={
            "model": "gpt-4", "messages": [{"role": "system", "content": "b"}, {"role": "user", "content": "hi"}],
        }, headers={"Authorization": f"Bearer {raw_key}"})

    with TestClient(app) as client:
        all_logs = client.post("/search/api/logs", json={"key_hashes": [key_hash]}).json()
        assert all_logs["pagination"]["total"] == 2

        fp0 = all_logs["items"][0]["conv_fingerprint"]
        filtered = client.post("/search/api/logs", json={
            "key_hashes": [key_hash],
            "conv_fingerprint": fp0,
        }).json()
        assert filtered["pagination"]["total"] == 1
        assert filtered["items"][0]["conv_fingerprint"] == fp0


def test_search_logs_filter_by_model(tmp_path):
    """search API 日志筛选：按 model"""
    raw_key = "sk-model-filter-key"
    from llm_passthough_log.storage import hash_api_key

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"},
                              json={"id": "r1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    app = create_app(build_settings(tmp_path), downstream_transport=httpx.MockTransport(handler))
    key_hash = hash_api_key(raw_key)

    with TestClient(app) as client:
        client.post("/v1/chat/completions", json={"model": "gpt-4", "messages": [{"role": "user", "content": "a"}]},
                     headers={"Authorization": f"Bearer {raw_key}"})
        client.post("/v1/chat/completions", json={"model": "claude-3", "messages": [{"role": "user", "content": "b"}]},
                     headers={"Authorization": f"Bearer {raw_key}"})

    with TestClient(app) as client:
        all_resp = client.post("/search/api/logs", json={"key_hashes": [key_hash]}).json()
        assert all_resp["pagination"]["total"] == 2

        gpt = client.post("/search/api/logs", json={"key_hashes": [key_hash], "model": "gpt-4"}).json()
        assert gpt["pagination"]["total"] == 1
        assert gpt["items"][0]["request_model"] == "gpt-4"


def test_search_logs_filter_by_stream(tmp_path):
    """search API 日志筛选：按 stream"""
    raw_key = "sk-stream-filter-key"
    from llm_passthough_log.storage import hash_api_key

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"},
                              json={"id": "r1", "choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    app = create_app(build_settings(tmp_path), downstream_transport=httpx.MockTransport(handler))
    key_hash = hash_api_key(raw_key)

    with TestClient(app) as client:
        client.post("/v1/chat/completions",
                     json={"model": "gpt-4", "stream": False, "messages": [{"role": "user", "content": "a"}]},
                     headers={"Authorization": f"Bearer {raw_key}"})

    with TestClient(app) as client:
        resp = client.post("/search/api/logs", json={"key_hashes": [key_hash], "stream": "false"}).json()
        assert resp["pagination"]["total"] == 1

        resp = client.post("/search/api/logs", json={"key_hashes": [key_hash], "stream": "true"}).json()
        assert resp["pagination"]["total"] == 0


# ════════════════ Misc Endpoints ════════════════


def test_healthz_endpoint(tmp_path):
    """/healthz 应返回 200"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )
    with TestClient(app) as client:
        resp = client.get("/healthz")
        assert resp.status_code == 200


def test_search_page_serves_html(tmp_path):
    """/search 应返回 HTML"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )
    with TestClient(app) as client:
        resp = client.get("/search")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]


def test_admin_logout(tmp_path):
    """admin logout 应使 session 失效"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )
    with TestClient(app) as client:
        admin_headers = login_admin(client)
        resp = client.get("/admin/api/overview", headers=admin_headers)
        assert resp.status_code == 200

        resp = client.post("/admin/api/logout", headers=admin_headers)
        assert resp.status_code == 200

        resp = client.get("/admin/api/overview", headers=admin_headers)
        assert resp.status_code == 401
