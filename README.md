# 云汀图床（传图 → 拿链接 · Web 版）

配合「阿里云 OSS → Cloudflare 免流」教程使用的图床，界面优雅、功能完整：

- **存储**：阿里云 OSS 私有桶（海外地域，如香港）
- **分发**：Cloudflare 免流域名（你的 `2.com`），图片访问不经过任何函数，无限流量
- **上传**：浏览器直传 OSS，函数只负责签发 5 分钟有效的直传 Policy，**每传 1 张图仅调用 1 次函数**
- **一套代码，三个平台可跑**：腾讯 EdgeOne Makers / 阿里云 ESA Pages + 边缘函数 / Cloudflare Workers & Pages

## 功能

- 🔒 密码登录门禁（UPLOAD_PASSWORD，本机记住自动解锁）
- 🖼️ 拖拽 / 粘贴 / 点选上传，**支持多选批量上传**，队列式进度显示
- 🗜️ 可选智能压缩为 WebP（画质可调，压缩后更大则自动保留原图）
- ☁️ 云端图库：浏览桶内文件、文件名搜索筛选、分页加载、骨架屏加载动画
- 🔍 大图灯箱预览：复制链接 / Markdown、**双次点击确认删除**（直接从 OSS 删除）
- 🔗 上传后一键复制 URL / Markdown / HTML / BBCode
- 🕘 本机历史记录（localStorage，不上传）
- 📱 响应式布局，手机可用

## 目录结构

```
├── index.html                    # 前端页面（登录门禁/批量上传/云端图库/灯箱/历史记录）
├── functions/api/
│   ├── sign.js                   # 上传签名 + 密码预检（EdgeOne Pages / CF Pages 直接用）
│   ├── list.js                   # 列出桶内文件
│   └── delete.js                 # 删除桶内文件
└── adapters/
    ├── cloudflare-workers.js     # Cloudflare Workers 独立版（含全部三个接口）
    └── esa-edge-function.js      # 阿里云 ESA 边缘函数版（含全部三个接口）
```

## 准备工作（先完成免流教程）

1. 按教程建好 OSS 海外私有桶、CF IP 白名单、自定义主机名，确认 `https://2.com/某张图` 能正常访问
2. **额外做一步：配置 Bucket 的 CORS**（教程里没有，但浏览器直传需要）：
   - OSS 控制台 → 你的 Bucket → 数据安全 → 跨域设置 → 创建规则
   - 来源（AllowedOrigin）：填你的图床站点域名，如 `https://img-admin.edgeone.app`（调试期可先用 `*`）
   - 方法（AllowedMethods）：`POST`
   - 允许的 Header（AllowedHeaders）：`*`
   - 暴露 Header（ExposeHeaders）：`ETag`
3. 建议创建 **RAM 子账号 AccessKey**，只授权这一个 Bucket 的 `oss:PutObject`、`oss:ListObjects`、`oss:DeleteObject` 权限，别用主账号 AK

## 环境变量（三平台通用）

| 变量 | 示例 | 说明 |
|---|---|---|
| `OSS_ACCESS_KEY_ID` | `LTAI5t...` | RAM 子账号 AK |
| `OSS_ACCESS_KEY_SECRET` | `xxxx` | 对应 SK |
| `OSS_BUCKET` | `my-img` | Bucket 名 |
| `OSS_ENDPOINT` | `oss-cn-hongkong.aliyuncs.com` | Bucket 概览页底部可查 |
| `PUBLIC_URL_BASE` | `https://img.example.com` | 教程里的访问域名 `2.com` |
| `UPLOAD_PASSWORD` | （可选） | 设置后前端需输密码才能传图 |
| `MAX_SIZE_MB` | （可选，默认 10） | 单文件大小上限 |

## 部署方式一：EdgeOne Makers（推荐）

1. 把本目录推送到 CNB / GitHub 仓库（**环境变量不要写进代码**，在控制台配）
2. EdgeOne Pages → 新建项目 → 导入仓库 → 根目录直接部署（`functions/api/sign.js` 会自动注册为 `/api/sign`）
3. 项目设置 → 环境变量，填上表 7 个变量
4. 打开分配的 `.edgeone.app` 域名即可使用；可绑自定义域名（国内节点需备案）

函数消耗：每传 1 张图 = 1 次请求，免费额度 300 万次/月，等于用不完。

## 部署方式二：Cloudflare Workers

1. Workers 控制台 → Create Worker → 粘贴 `adapters/cloudflare-workers.js` → Deploy
2. Settings → Variables and Secrets 配置环境变量
3. 前端 `index.html` 部署在 CF Pages（同一仓库时 Pages Functions 可直接用 `functions/api/sign.js`，无需 Worker），或任何静态托管
4. 若前端和 Worker 不同域，已内置 CORS，无需额外配置

## 部署方式三：阿里云 ESA

1. ESA 控制台 → 边缘函数 → 新建 → 粘贴 `adapters/esa-edge-function.js` → 发布
2. 若 ESA 支持环境变量则配置变量；不支持就把文件顶部 `CONFIG` 填好（**填完别再提交到公开仓库**）
3. 把图床管理域名关联到该函数；`index.html` 部署在 ESA Pages 或任意静态托管
4. 免费版边缘函数 10 万次/天，每张图仅 1 次，够用

## 使用

打开页面 → **先过登录门禁**（输入 `UPLOAD_PASSWORD` 对应的密码，验证通过才会显示上传界面，密码本机记住、下次自动解锁）→ 拖图 / 粘贴 / 点选 → 自动压缩 WebP（可关）→ 自动复制四种格式链接。

**云端图库**：解锁后自动加载 OSS 桶内 `img/` 前缀下的文件，支持分页「加载更多」和「刷新」，点击缩略图即复制图片链接，悬停可查看文件名/大小/上传时间。

历史记录只存在浏览器 localStorage，不上传、不同步。页脚「退出登录」可清除本机保存的密码。

> 安全说明：登录门禁只是前端体验层，真正的拦截在函数里——`/api/sign` 和 `/api/list` 都会校验密码，密码不对直接 401。若未设置 `UPLOAD_PASSWORD`，门禁会自动放行（不建议裸奔）。

## 接口一览

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/sign` | POST | 上传签名；`{check:true}` 时为密码预检 |
| `/api/list` | POST | 列出桶内 `img/` 前缀文件，`{password, token?}`，每页 60 条 |
| `/api/delete` | POST | 删除桶内文件，`{password, key}`，仅允许 `img/` 前缀 |

## 费用说明

- 函数：三平台免费额度内，每张图 1 次调用，可忽略
- 图片访问流量：走 CF 带宽联盟回源免流 + CF 免费 CDN，不产生费用
- 唯一固定成本：**OSS 存储费**（海外标准存储，每月每 GB 约 0.1 元人民币量级）
- ⚠️ 带宽联盟政策要求源站为非中国大陆地域的标准型存储桶；建议用**阿里云国际版**账号（含每月 1 亿次免费请求等权益），上车后先小额实测一张账单确认
- ⚠️ OSS 是后付费：保持账户有少量余额 + 开通余额告警，避免欠费停服导致数据进入释放倒计时

## 安全提示

- AccessKey 只存于服务端环境变量，前端不可见
- 页面带登录门禁，签名函数双重校验密码（预检 + 签发时），密码不对拿不到签名
- 图片路径为 `img/日期/32位随机串.扩展名`，不可枚举；桶本身私有 + 仅 CF IP 段只读白名单
- **必须设置 `UPLOAD_PASSWORD`**，否则任何人打开页面都能往你桶里传图
