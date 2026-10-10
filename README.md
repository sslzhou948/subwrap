# subwrap —— Clash 订阅转发服务（隐藏真实订阅 URL）

## 它做什么

纯反向代理，只做一件事：**隐藏真实的上游订阅地址**。

```
分享对象
  → HTTPS → 你的域名 (NPM 在 Mac 上终止 TLS，192.168.3.155)
  → 内网 HTTP → 群晖转发服务 (192.168.3.150:18080)
  → Tailscale 加密隧道 → VPS 上游订阅 (100.x)
```

- 不存任何 YAML 文件、不合并模板、不做缓存——每次请求实时转发上游，拿到的永远是最新内容；
- 上游 URL（含账号密码）只存在于群晖本机的 `.env`，不出现在下发内容与日志里；
- 每人一条专属分享链接：`https://<你的域名>/s/<8位token>`（如 `/s/aB3xK9qZ`），可在管理界面随时**禁用 / 换 token / 删除**，被停用的人只会看到 404；
- 二维码分享：每条链接旁边有点「二维码」按钮，打开后保存图片发给对方，对方扫码即可导入（需先在管理界面填好公网域名）。

> 说明：转发的就是上游订阅的原始内容（你 VPS 面板生成的那份）。
> 你自己三端用的那份统一 YAML（含精心调过的规则/DNS/策略组）
> 继续由你手动维护、手动导入各客户端——转发服务不碰它。

镜像由本仓库的 GitHub Actions 自动构建并推送到 GHCR，群晖上直接拉取即可，不用自己构建：

```
ghcr.io/sslzhou948/subwrap:latest
```

## 部署步骤（群晖，拉取版）

### 0. 群晖装 Tailscale（一次性）

1. 群晖套件中心安装 Tailscale，用你的账号登录；
2. 确认群晖能看到 VPS 节点在线，记下 VPS 的 Tailscale IP（`100.x.x.x`）；
3. **关闭密钥过期**：Tailscale 管理后台 → Machines → VPS 和群晖 → `⋯` → Disable key expiry（默认 180 天过期，不关会悄悄掉线）。

### 1. 准备文件

在群晖新建目录（例如 `/volume1/docker/subwrap`），放入：

```
/volume1/docker/subwrap/
├── docker-compose.yml   ← 本仓库的拉取版（从 GHCR 拉镜像）
├── .env                 ← 按 .env.example 填写（见下）
└── data/                ← 空目录即可，配置会自动持久化到 data/config.json
```

`.env` 按 `.env.example` 复制后填写（**只用于首次启动，之后在 Web 界面里改；含敏感信息，勿外传**）：

| 变量 | 填什么 |
|---|---|
| `SUB_TOKEN` | 任意随机字符串（如 `openssl rand -hex 8`）。首次启动时生成一条"默认"链接；之后在 Web 界面按人新建专属链接（自动生成 8 位 token） |
| `UPSTREAM_URL` | 上游订阅地址，**必须把 host 换成 VPS 的 Tailscale IP**（如 `http://100.x.x.x:端口/路径`） |
| `ADMIN_PASSWORD` | Web 管理界面的登录密码；不填则禁用管理界面 |
| `PUBLIC_BASE_URL` | 公网域名（选填，如 `https://sub.你的域名`），仅用于在管理界面拼接显示完整分享链接 |

### 2. 启动容器

群晖 Container Manager → 项目 → 新增 → 选择 `/volume1/docker/subwrap` 目录 → 启动。
它会自动从 GHCR 拉取 `ghcr.io/sslzhou948/subwrap:latest` 镜像，无需本地构建。

### 3. Web 管理界面（内网）

浏览器打开 `http://192.168.3.150:18081/admin`，用 `ADMIN_PASSWORD` 登录：

- **分享链接**：给每个人建一条专属链接（填备注如"张三"），一键复制；
  每条可单独**禁用 / 换 token / 删除**，即时生效——被停用的人拉取只会看到 404；
- **上游订阅**：查看/修改转发目标地址、`测试连通`按钮实时验证；
- **访问记录**：最近 50 次订阅拉取的时间、来源 IP、走的哪条链接、成功与否；
- **修改管理密码**、退出登录。

> ⚠️ 管理界面只在内网用，**不要在 NPM 里给它配反代**，不要暴露到公网。

### 4. 验证转发

```bash
# 健康检查
curl http://192.168.3.150:18080/healthz
# 应返回 {"ok": true, "mode": "forward"}

# 拉取订阅（把 <token> 换成你的 SUB_TOKEN），与直接访问上游 URL 的内容逐字节一致
curl -o via-wrap.yaml http://192.168.3.150:18080/s/<token>

# token 错误应返回 404
curl -o /dev/null -w "%{http_code}\n" http://192.168.3.150:18080/s/wrongtoken
```

### 5. NPM 配置（Mac，192.168.3.155）

NPM 管理界面 → Proxy Hosts → Add：

- Domain Names：`sub.<你的域名>`（DNS 先指到家庭公网 IP/已有的解析）
- Scheme：`http`，Forward Hostname/IP：`192.168.3.150`，Forward Port：`18080`
  （⚠️ 只反代 18080 转发端口，不要反代 18081 管理端口）
- 打开 Block Common Exploits；SSL 申请/沿用你的证书（Let's Encrypt）
- Access List 不用配——token 在 URL 路径里即是鉴权

之后分享链接：`https://sub.<你的域名>/s/<token>`（也可在管理界面直接复制）。

### 6. 日常维护

- **给新人开链接**：在 Web 管理界面"分享链接"里新建一条，填备注发出去；
- **停掉某人**：在管理界面把那条链接**禁用**（或换 token、或删除），即时生效，不用重建容器；
- **改上游地址**：在 Web 管理界面改，保存即生效；
- **更新镜像**：本仓库有代码更新并构建出新镜像后，在群晖项目里重新拉取镜像再重建容器即可（`data/` 里的配置不受影响）；
- **看日志**：Container Manager → 容器 → 日志（token 在日志里会被打码为 `/s/<token>`，上游 URL 不记日志）；
- 上游本身更新（VPS 面板改节点/规则）后，分享链接下次拉取即是新内容，无需动转发服务。

## 本仓库文件说明

| 文件 | 说明 |
|---|---|
| `app.py` | 转发服务主程序 |
| `qrcodegen.py` | 二维码生成库（MIT），勿删 |
| `Dockerfile` | 镜像构建文件（GitHub Actions 用，群晖上不用管） |
| `docker-compose.yml` | 拉取版 compose：群晖部署只用这个 + `.env` |
| `.env.example` | 环境变量模板 |
| `.github/workflows/docker-publish.yml` | 自动构建：main 分支推送后构建多架构镜像并推送到 GHCR |

## 本地构建（可选）

如果不想用 GHCR 的预构建镜像，也可以本地构建：

```bash
docker build -t subwrap .
```

然后把 `docker-compose.yml` 里的 `image: ghcr.io/sslzhou948/subwrap:latest` 改成 `build: .` 即可，其余不变。

## 故障排查

| 现象 | 查哪里 |
|---|---|
| 订阅返回 502 | 上游不可达：检查 `UPSTREAM_URL` 的 Tailscale IP 对吗？群晖上 `tailscale status` 里 VPS 在线吗？VPS 上订阅服务本身正常吗？ |
| 订阅 404 | token 不对，或路径不是 `/s/<token>` 格式 |
| 容器启动即退出 | `.env` 里 `SUB_TOKEN` / `UPSTREAM_URL` 没填（fail closed，日志会写明） |
| 拉取镜像失败/超时 | 群晖到 `ghcr.io` 的网络问题；可改用上面的本地构建方式 |
| 忘记管理密码 | 在 `.env` 填入新的 `ADMIN_PASSWORD` 后重建容器，即强制重置（启动日志会写"管理密码已强制重置"）；平时建议把该项清空，只在忘记时临时填入，以免重启后覆盖网页上改的密码 |

## 安全说明

- 上游订阅 URL（含账号密码）只存在于群晖本机的 `.env`，永远不会出现在下发内容、日志或 healthz 里；
- 下发内容与直接访问上游 URL 完全一致，转发服务不修改、不记录响应体；
- 下发配置里唯一的"敏感"是节点连接凭据——这是订阅能用的必要条件，**只发给被分享人**；
- 每条专属链接独立鉴权，链接只给对应的人；怀疑某条泄露就单独禁用/换 token，不影响其他人；
- Tailscale 节点密钥过期已关（步骤 0），ACL 收窄可在跑通后另行处理。
