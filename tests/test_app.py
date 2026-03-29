import gzip

import httpx
from fastapi.testclient import TestClient

from llm_passthough_log import app as app_module
from llm_passthough_log.app import create_app
from llm_passthough_log.config import Settings
from llm_passthough_log.storage import LogStore


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
        admin_api_key=None,
    )


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
        logs = client.get("/admin/api/logs").json()
        assert logs["pagination"]["total"] == 1
        assert logs["items"][0]["request_model"] == "gpt-test"
        detail = client.get(f"/admin/api/logs/{logs['items'][0]['id']}").json()
        assert detail["response_status"] == 200
        assert detail["request_body"]["messages"][0]["content"] == "hello"


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
        logs = client.get("/admin/api/logs").json()
        assert logs["pagination"]["total"] == 1
        detail = client.get(f"/admin/api/logs/{logs['items'][0]['id']}").json()
        assert detail["response_body"].startswith("data: {\"delta\":\"hello\"}")


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
    original_write = LogStore._write_entry_sync

    def flaky_write(self, entry):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("temporary write failure")
        return original_write(self, entry)

    monkeypatch.setattr(LogStore, "_write_entry_sync", flaky_write)

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
        logs = client.get("/admin/api/logs").json()
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

    def fake_async_http_transport(*, retries: int, http2: bool):
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
        # 创建用户
        resp = client.post("/admin/api/users", json={"name": "测试用户", "api_key": "sk-test-key-001"})
        assert resp.status_code == 200
        user = resp.json()
        uid = user["id"]
        assert user["name"] == "测试用户"
        assert user["api_key"] == "sk-test-key-001"
        assert user["enabled"] == 1

        # 列表
        resp = client.get("/admin/api/users")
        assert resp.status_code == 200
        data = resp.json()
        assert data["pagination"]["total"] == 1
        assert data["items"][0]["name"] == "测试用户"

        # 按名称搜索
        resp = client.get("/admin/api/users?q=测试")
        assert resp.json()["pagination"]["total"] == 1
        resp = client.get("/admin/api/users?q=不存在")
        assert resp.json()["pagination"]["total"] == 0

        # 获取详情
        resp = client.get(f"/admin/api/users/{uid}")
        assert resp.status_code == 200
        assert resp.json()["api_key"] == "sk-test-key-001"

        # 更新
        resp = client.put(f"/admin/api/users/{uid}", json={"name": "改名了", "enabled": False})
        assert resp.status_code == 200
        assert resp.json()["name"] == "改名了"
        assert resp.json()["enabled"] == 0

        # 删除
        resp = client.delete(f"/admin/api/users/{uid}")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

        # 确认已删除
        resp = client.get(f"/admin/api/users/{uid}")
        assert resp.status_code == 404


def test_user_create_auto_generates_key(tmp_path):
    """不传 api_key 时自动生成 sk- 前缀密钥"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        resp = client.post("/admin/api/users", json={"name": "自动生成Key"})
        assert resp.status_code == 200
        assert resp.json()["api_key"].startswith("sk-")
        assert len(resp.json()["api_key"]) > 10


def test_user_create_requires_name(tmp_path):
    """name 为空时返回 422"""
    app = create_app(
        build_settings(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        resp = client.post("/admin/api/users", json={"name": ""})
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
        # 先创建一个带自定义 downstream 的用户
        resp = client.post("/admin/api/users", json={
            "name": "custom-user",
            "api_key": "sk-custom-user-key",
            "downstream_url": "https://custom.api.test",
            "downstream_apikey": "sk-real-provider-key",
        })
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
        # 创建 provider
        resp = client.post("/admin/api/providers", json={
            "name": "OpenAI",
            "prefix_path": "openai",
            "downstream_url": "https://api.openai.com",
            "input_price": 2.5,
            "output_price": 10.0,
        })
        assert resp.status_code == 200
        prov = resp.json()
        pid = prov["id"]
        assert prov["name"] == "OpenAI"
        assert prov["prefix_path"] == "openai"

        # 列表
        resp = client.get("/admin/api/providers")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["name"] == "OpenAI"

        # 获取详情
        resp = client.get(f"/admin/api/providers/{pid}")
        assert resp.status_code == 200
        assert resp.json()["input_price"] == 2.5

        # 更新
        resp = client.put(f"/admin/api/providers/{pid}", json={"name": "OpenAI Updated", "output_price": 15.0})
        assert resp.status_code == 200
        assert resp.json()["name"] == "OpenAI Updated"
        assert resp.json()["output_price"] == 15.0

        # 删除
        resp = client.delete(f"/admin/api/providers/{pid}")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

        # 确认已删除
        resp = client.get(f"/admin/api/providers/{pid}")
        assert resp.status_code == 404


# ════════════════ Auth & Permissions ════════════════


def build_settings_with_auth(tmp_path):
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
        admin_api_key="sk-master-admin",
    )


def test_auth_required_when_admin_key_set(tmp_path):
    """设置 ADMIN_API_KEY 后，无认证请求返回 401"""
    app = create_app(
        build_settings_with_auth(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        # 无 key 应 401
        resp = client.get("/admin/api/overview")
        assert resp.status_code == 401

        # 错误 key 也应 401
        resp = client.get("/admin/api/overview", headers={"X-Api-Key": "wrong-key"})
        assert resp.status_code == 401

        # 正确 admin key 应 200
        resp = client.get("/admin/api/overview", headers={"X-Api-Key": "sk-master-admin"})
        assert resp.status_code == 200


def test_user_role_sees_filtered_data(tmp_path):
    """user 角色只能看到自己有权限的 provider 的数据"""
    app = create_app(
        build_settings_with_auth(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )
    admin_hdr = {"X-Api-Key": "sk-master-admin"}

    with TestClient(app) as client:
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
            "api_key": "sk-viewer-key",
            "role": "user",
            "provider_ids": [prov_id],
        }, headers=admin_hdr)
        assert resp.status_code == 200

        # user 角色不能管理 providers
        resp = client.get("/admin/api/providers", headers={"X-Api-Key": "sk-viewer-key"})
        assert resp.status_code == 403

        # user 角色不能管理 users
        resp = client.get("/admin/api/users", headers={"X-Api-Key": "sk-viewer-key"})
        assert resp.status_code == 403

        # user 可以查看 overview 和 logs
        resp = client.get("/admin/api/overview", headers={"X-Api-Key": "sk-viewer-key"})
        assert resp.status_code == 200

        resp = client.get("/admin/api/logs", headers={"X-Api-Key": "sk-viewer-key"})
        assert resp.status_code == 200


def test_session_returns_user_info(tmp_path):
    """session 端点返回用户信息和角色"""
    app = create_app(
        build_settings_with_auth(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )

    with TestClient(app) as client:
        # admin key
        resp = client.get("/admin/api/session", headers={"X-Api-Key": "sk-master-admin"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["user"]["role"] == "admin"

        # 无 key
        resp = client.get("/admin/api/session")
        assert resp.status_code == 401


def test_password_login_flow(tmp_path):
    """用户名+密码登录流程"""
    app = create_app(
        build_settings_with_auth(tmp_path),
        downstream_transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True})),
    )
    admin_hdr = {"X-Api-Key": "sk-master-admin"}

    with TestClient(app) as client:
        # 创建带密码的用户
        resp = client.post("/admin/api/users", json={
            "name": "testuser",
            "password": "mypassword123",
            "role": "user",
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
        assert "api_key" in data  # 返回 api_key 用于后续请求

        # 用返回的 api_key 访问 session
        resp = client.get("/admin/api/session", headers={"X-Api-Key": data["api_key"]})
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
