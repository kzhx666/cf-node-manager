# CF 优选 Pro（Docker 一键部署版）

这是一个轻量的 Web 节点管理/订阅生成器：
- 面板里维护「优选 IP 库」与「订阅来源」
- 同步后缓存节点
- 通过 `/sub` 输出多种订阅格式（Base64 URI / Clash / sing-box）

> 本仓库已包含：Hy2 端口跳跃（mport/ports）、AnyTLS、ShadowTLS、NaiveProxy 的识别与生成支持。

---

## 目录结构

```text
.
├── app.py
├── templates/
│   └── index.html
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── data/               # 运行后自动生成（持久化数据/日志/GeoIP）
```

---

## 快速开始（Docker Compose）

```bash
git clone https://github.com/<你的github用户名>/<仓库名>.git
cd <仓库名>

cp .env.example .env
# 编辑 .env，把 WEB_PASSWORD 改成你自己的

mkdir -p data
# 让容器用户可写（容器内 uid=10001）
chown -R 10001:10001 data

docker compose up -d --build
```

浏览器访问：
- `http://服务器IP:5000/`

---

## 订阅输出接口

面板里会给你生成订阅链接，本质是：

- Base64（默认）：
  - `http://服务器IP:8080/sub?token=你的token`
- Clash：
  - `http://服务器IP:8080/sub?token=你的token&flag=clash`
- sing-box：
  - `http://服务器IP:8080/sub?token=你的token&flag=singbox`

常用筛选：
- `filter=关键词` 只保留包含关键词的节点
- `exclude=关键词` 排除包含关键词的节点
- `raw=1` 输出原始节点（不做优选 IP 替换）

示例：
```text
/sub?token=xxxx&flag=clash&filter=HK&exclude=游戏&raw=0
```

---

## 环境变量

- `WEB_PASSWORD`：面板登录密码（也作为 `/sub` 的默认 token）
- `TZ`：容器时区

---

## 本地运行（不用 Docker）

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export WEB_PASSWORD=admin
python app.py
# 默认监听 0.0.0.0:5000
```

---

## 发布镜像到 GHCR（可选）

如果你想做到别人可以：

```bash
docker pull ghcr.io/<你的github用户名>/<仓库名>:latest
```

可以启用 GitHub Actions 工作流（见 `.github/workflows/docker-publish.yml`）。

---

## 安全建议

- **一定要改 `WEB_PASSWORD`**
- 建议放在反向代理（Nginx/Caddy）后加 HTTPS
- 面板服务不要直接暴露在公网（或至少加防火墙 / 白名单）

