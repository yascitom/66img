# 云窝（传图/视频/文件 → 拿链接 · Web 版）

私有图床 + 小型网盘：配合「阿里云 OSS → Cloudflare 免流」教程使用，界面优雅、功能完整：

> 📖 配套教程：[奈溪论坛 · 阿里云 OSS + Cloudflare 免流图床教程](https://forum.naixi.net/thread-9085-1-1.html) ｜ [NodeSeek · 同教程帖子](https://www.nodeseek.com/post-586574-1)

- **存储**：阿里云 OSS 私有桶（海外地域，如香港）
- **分发**：Cloudflare 免流域名（你的 `2.com`），文件访问不经过任何函数，无限流量
- **上传**：浏览器直传 OSS，函数只负责签名、不接触文件内容
  - **小文件（≤10MB）**：PostObject 表单直传，每传 1 个文件仅调用 1 次函数
  - **大文件（>10MB）**：**分片上传（Multipart）**——每片 10MB 独立签名、即签即传，**慢网络不限总时长**；中断后重选同一文件**自动断点续传**，失败分片自动重签重试
- **一套代码，三个平台可跑**：腾讯 EdgeOne Makers / 阿里云 ESA Pages + 边缘函数 / Cloudflare Workers & Pages

## 目录规则（自动归类）

上传时按扩展名自动落到对应目录，前端可切换目录浏览：

| 目录 | 内容 |
|---|---|
| `upweb/img/` | 图片：jpg jpeg png gif webp svg avif bmp ico tiff |
| `upweb/video/` | 视频：mp4 webm mov mkv m4v avi flv ts |
| `upweb/other/` | 其他一切：压缩包、文档、音频、安装包… |

## 功能

- 🔒 密码登录门禁（UPLOAD_PASSWORD，本机记住自动解锁）
- 🗂️ 任意文件上传：图片 / 视频 / 压缩包 / 文档，拖拽 / 粘贴 / 点选，**支持多选批量上传**，队列式进度显示
- 🧩 **大文件分片上传**：>10MB 自动走 OSS Multipart，逐片进度百分比；**断点续传**（进度存本机，中断/刷新/关页面后重选同一文件自动接着传）；分片失败自动重试 3 次并重新签名；ETag 读不到时本地计算分片 MD5 兜底
- 🗜️ 图片可选智能压缩为 WebP（画质可调，压缩后更大则自动保留原图）
- ☁️ 云端文件：目录标签页切换（全部 / 图片 / 视频 / 其他）、文件名搜索筛选、分页加载、骨架屏
- 🎬 灯箱预览：图片看大图、**视频在线播放**、其他文件显示图标并可打开/下载；复制链接 / Markdown、**双次点击确认删除**（直接从 OSS 删除）
- 🔗 上传后一键复制 URL / Markdown
- 🕘 本机历史记录（localStorage，不上传）
- 📱 响应式布局，手机可用

## 目录结构

```
├── index.html                    # 前端页面（登录门禁/分片上传/断点续传/云端文件/灯箱/历史记录）
├── functions/api/
│   ├── sign.js                   # 小文件上传签名 + 密码预检（EdgeOne Pages / CF Pages 直接用）
│   ├── list.js                   # 列出桶内文件（支持目录参数）
│   ├── delete.js                 # 删除桶内文件
│   └── multipart.js              # 大文件分片上传（init/part签名/complete/abort）
└── adapters/
    ├── cloudflare-workers.js     # Cloudflare Workers 独立版（含全部四个接口）
    └── esa-edge-function.js      # 阿里云 ESA 边缘函数版（含全部四个接口）
```

## 准备工作（先完成免流教程）

1. 按教程建好 OSS 海外私有桶、CF IP 白名单、自定义主机名，确认 `https://2.com/某张图` 能正常访问
2. **额外做一步：配置 Bucket 的 CORS**（教程里没有，但浏览器直传需要；**分片上传必须有 PUT**）：
   - OSS 控制台 → 你的 Bucket → 数据安全 → 跨域设置 → 创建规则
   - 来源（AllowedOrigin）：填你的图床站点域名，如 `https://img-admin.edgeone.app`（调试期可先用 `*`）
   - 方法（AllowedMethods）：`POST`、`PUT`（⚠️ 老配置只开了 POST，分片上传会失败，务必补上 PUT）
   - 允许的 Header（AllowedHeaders）：`*`
   - 暴露 Header（ExposeHeaders）：`ETag`（建议配；即使不配，前端也会本地计算分片 MD5 兜底，不影响上传）
   - ⚠️ **多条规则时注意**：OSS 按「第一条匹配的规则」生效。若存在 `*` 通配规则排在前面，会抢先匹配你的站点——请给它也加上 ETag 暴露头，或直接删除多余的通配规则
   - ⚠️ 跨域规则**生效有最长 15 分钟延迟**；改完后若浏览器仍报旧错，用无痕窗口重试（避开预检缓存）
3. **（强烈建议）配置生命周期规则自动清理残留分片**：分片上传中断后，已传的分片会暂存 OSS 并计费。OSS 控制台 → 你的 Bucket → 数据管理 → 生命周期 → 创建规则 → 前缀 `upweb/` → 「碎片管理」勾选**过期碎片 3 天后删除**。这样任何烂尾上传都会自动清理，**不会悄悄产生存储费**
4. 建议创建 **RAM 子账号 AccessKey**，只授权这一个 Bucket 的 `oss:PutObject`、`oss:ListObjects`、`oss:DeleteObject`、`oss:AbortMultipartUpload` 等权限（直接给 `oss:*` 限定该桶最省事），别用主账号 AK

## 环境变量（三平台通用）

| 变量 | 示例 | 说明 |
|---|---|---|
| `OSS_ACCESS_KEY_ID` | `LTAI5t...` | RAM 子账号 AK |
| `OSS_ACCESS_KEY_SECRET` | `xxxx` | 对应 SK |
| `OSS_BUCKET` | `my-img` | Bucket 名 |
| `OSS_ENDPOINT` | `oss-cn-hongkong.aliyuncs.com` | Bucket 概览页底部可查 |
| `PUBLIC_URL_BASE` | `https://img.example.com` | 教程里的访问域名 `2.com` |
| `UPLOAD_PASSWORD` | （可选） | 设置后前端需输密码才能上传 |
| `MAX_SIZE_MB` | （可选，默认 100） | 单文件大小上限；分片上传已突破单请求限制，传大视频可设 500~2000 |
| `PART_SIZE_MB` | （可选，默认 10） | 分片大小（MB），范围 5~100。网络差调小（重试代价小），网络好调大（签名次数少） |

## 部署方式一：EdgeOne Makers（推荐）

1. 把本目录推送到 CNB / GitHub 仓库（**环境变量不要写进代码**，在控制台配）
2. EdgeOne Pages → 新建项目 → 导入仓库 → 根目录直接部署（`functions/api/*.js` 会自动注册为 `/api/*`）
3. 项目设置 → 环境变量，填上表中的变量
4. 打开分配的 `.edgeone.app` 域名即可使用；可绑自定义域名（国内节点需备案）

函数消耗：小文件每传 1 个 = 1 次请求；大文件分片模式 = 每片 1 次签名请求（几 KB），免费额度 300 万次/月，等于用不完。

## 部署方式二：Cloudflare Workers

1. Workers 控制台 → Create Worker → 粘贴 `adapters/cloudflare-workers.js` → Deploy
2. Settings → Variables and Secrets 配置环境变量
3. 前端 `index.html` 部署在 CF Pages（同一仓库时 Pages Functions 可直接用 `functions/api/*.js`，无需 Worker），或任何静态托管
4. 若前端和 Worker 不同域，已内置 CORS，无需额外配置

## 部署方式三：阿里云 ESA

1. ESA 控制台 → 边缘函数 → 新建 → 粘贴 `adapters/esa-edge-function.js` → 发布
2. 若 ESA 支持环境变量则配置变量；不支持就把文件顶部 `CONFIG` 填好（**填完别再提交到公开仓库**）
3. 把云盘管理域名关联到该函数；`index.html` 部署在 ESA Pages 或任意静态托管
4. 免费版边缘函数 10 万次/天，小文件每个仅 1 次，大文件每片 1 次签名，够用

## 使用

打开页面 → **先过登录门禁**（输入 `UPLOAD_PASSWORD` 对应的密码，本机记住、下次自动解锁）→ 拖文件 / 粘贴图片 / 点选 → 自动归类目录 → 一键复制链接。

**云端文件**：解锁后自动加载 OSS 桶内 `upweb/` 下的文件，顶部标签页切换目录（全部/图片/视频/其他），支持分页「加载更多」、「刷新」和文件名筛选；点击缩略图打开灯箱——图片看大图、视频直接播放、其他文件可打开/下载，悬停查看文件名。

历史记录只存在浏览器 localStorage，不上传、不同步。页脚「退出登录」可清除本机保存的密码。

> 安全说明：登录门禁只是前端体验层，真正的拦截在函数里——`/api/sign`、`/api/multipart`、`/api/list`、`/api/delete` 都会校验密码，密码不对直接 401；分片接口的 key 强制 `upweb/` 前缀白名单，无法越权操作桶内其他对象。若未设置 `UPLOAD_PASSWORD`，门禁会自动放行（不建议裸奔）。

## 接口一览

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/sign` | POST | 小文件上传签名（PostObject Policy），按扩展名自动归类目录；`{check:true}` 时为密码预检 |
| `/api/multipart` | POST | 大文件分片上传：`action=init` 初始化（返回 uploadId+key+partSize）；`action=part` 为单个分片签发 1 小时有效的预签名 URL；`action=complete` 合并分片；`action=abort` 清理残留分片。全程密钥不出服务端 |
| `/api/list` | POST | 列出文件，`{password, token?, dir?}`，dir ∈ `all/img/video/other`，每页 60 条 |
| `/api/delete` | POST | 删除文件，`{password, key}`，仅允许 `upweb/` 前缀 |

## 分片上传与慢网络说明

- **为什么分片能解决「上传超过 10 分钟」**：PostObject 的 Policy 只有 10 分钟有效期，慢网络传大文件可能拖到过期；分片模式下**每个分片单独申请预签名 URL（1 小时有效）、即签即传**，总上传时长不受任何单一签名限制——哪怕 1GB 文件传一晚上也没问题。
- **断点续传**：已成功分片保存在 OSS 服务端，进度记录在浏览器 localStorage。网络中断、刷新页面、甚至隔天再传——重新选择**同一个文件**即自动跳过已传分片继续上传。若 OSS 侧会话已过期（如被生命周期规则清理），前端会自动清掉本地进度重新整个上传。
- **ETag 双保险**：合并分片需要每片的 ETag。前端优先读取 OSS 响应头里的 ETag（需 CORS 暴露），读不到时用本地计算的分片 MD5（二者本来相等），因此 CORS 暴露头配不配都能传。
- **小文件的兜底**：≤10MB 文件仍走 PostObject 一次直传；若慢网络拖到 Policy 过期，前端检测到 `Policy expired` 会**自动重签重传一次**。
- **阈值**：前端固定以 10MB 为界选择两条通道，与服务端默认 `PART_SIZE_MB=10` 对齐。

## 费用说明

- 函数：三平台免费额度内，小文件 1 次调用/个、大文件每片 1 次签名调用，可忽略
- 文件访问流量：走 CF 带宽联盟回源免流 + CF 免费 CDN，不产生费用
- 唯一固定成本：**OSS 存储费**（海外标准存储，每月每 GB 约 0.1 元人民币量级）
- ⚠️ 带宽联盟政策要求源站为非中国大陆地域的标准型存储桶；建议用**阿里云国际版**账号（含每月 1 亿次免费请求等权益），上车后先小额实测一张账单确认
- ⚠️ OSS 是后付费：保持账户有少量余额 + 开通余额告警，避免欠费停服导致数据进入释放倒计时

## 安全提示

- AccessKey 只存于服务端环境变量，前端不可见
- 页面带登录门禁，四个接口都校验密码，密码不对拿不到签名、看不到列表、删不了文件
- 文件路径为 `upweb/<类型>/日期/32位随机串.扩展名`，不可枚举；桶本身私有 + 仅 CF IP 段只读白名单
- **必须设置 `UPLOAD_PASSWORD`**，否则任何人打开页面都能往你桶里传文件
