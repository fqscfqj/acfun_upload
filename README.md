# AcFun 视频上传工具

这是一个用于将视频上传到 AcFun (acfun.cn) 的 Python 脚本。
它支持通过命令行进行操作，并管理登录状态（通过 Cookie 文件）。

## 功能特性

*   通过命令行上传视频和封面。
*   设置视频标题、简介、标签、分区等信息。
*   支持原创和转载类型。
*   自动管理登录 Cookie (保存到 `config/acfun_cookies.txt`)。
*   支持通过命令行参数提供用户名和密码进行登录。
*   多线程分块上传视频和封面，提高上传效率。
*   详细的日志输出。

## 环境要求

*   Python 3.7+
*   `requests` 库

您可以通过以下命令安装所需依赖：

```bash
pip install -r requirements.txt
```

## 使用方法

脚本的主要功能通过 `acfun.py` 实现，可以直接通过命令行调用。

### 命令格式

```bash
python acfun.py [参数]
```

### 主要参数

*   `-vf`, `--video_file` (必填): 视频文件的完整路径。
*   `-cf`, `--cover_file` (必填): 封面图片的完整路径。
*   `-t`, `--title` (必填): 稿件的标题。
*   `-cid`, `--channel_id` (必填): AcFun 的分区频道 ID (例如 `63` 代表游戏中心-单机游戏)。
*   `-u`, `--username`: 您的 AcFun 用户名 (用于登录，如果 Cookie 无效或不存在)。
*   `-p`, `--password`: 您的 AcFun 密码。
*   `-d`, `--description`: 稿件的简介 (默认为空)。
*   `--tags`: 稿件的标签列表，多个标签用空格分隔 (例如: `--tags "游戏" "攻略"`)。
*   `--type`: 投稿类型，`1` 代表转载，`3` 代表原创 (默认为 `3`)。
*   `--original_link`: 如果是转载 (`--type 1`)，请提供原始视频的链接。
*   `--cookie_file`: 指定自定义的 Cookie 文件路径 (默认为 `config/acfun_cookies.txt`)。
*   `--max_workers`: 上传时使用的最大线程数 (默认为 `5`)。
*   `-h`, `--help`: 显示帮助信息。

### 示例命令

假设您在项目根目录 (`d:\github\acfun_upload\`) 下，并且视频文件为 `Test.mp4`，封面为 `Test.png`，都位于根目录：

```bash
python acfun.py ^
    -vf Test.mp4 ^
    -cf Test.png ^
    -t "我的精彩游戏时刻" ^
    -d "这是一段精彩的游戏视频记录！" ^
    --tags "单机游戏" "精彩集锦" "娱乐" ^
    -cid 63 ^
    --type 3 ^
    -u your_username ^
    -p your_password
```

*(Windows 命令行中 `^` 用于换行，Linux/macOS 中使用 `\`)*

**请替换 `your_username` 和 `your_password` 为您的实际 AcFun 账号信息。**

### 登录与 Cookie

*   `config/acfun_cookies.txt` 文件可以手动创建（包含有效的Cookie信息）或由程序在首次成功登录后自动生成。
*   后续运行时，脚本会尝试从此文件加载 Cookie。如果 Cookie 有效，则无需再次输入用户名和密码。
*   如果 Cookie 失效或文件不存在，您需要在命令行中通过 `-u` 和 `-p` 参数提供用户名和密码进行登录。
*   您可以通过 `--cookie_file` 参数指定其他的 Cookie 文件路径。

## 项目结构

```
d:\github\acfun_upload/
├── .gitignore
├── LICENSE
├── README.md
├── acfun.py                  # AcFun上传核心逻辑和命令行接口
├── config/                   # 配置文件目录
│   └── acfun_cookies.txt     # 存储登录Cookie
├── requirements.txt          # 项目依赖
```

## 注意事项

*   请确保提供的文件路径正确无误。
*   频道 ID (`-cid`) 需要是 AcFun 平台定义的有效 ID。
*   如果上传失败，请检查命令行的日志输出以获取详细错误信息。

## 贡献

欢迎提交 Pull Requests 或 Issues 来改进此项目。

## 许可证

本项目采用 [MIT 许可证](LICENSE)。