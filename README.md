# KGG to MP3

一个面向 Windows 的本地批处理脚本：读取酷狗客户端本机 `KGMusicV3.db` 中已有的逐曲密钥，解密用户有权访问的 KGG/KGM v5 文件，并输出标准 MP3。

> [!IMPORTANT]
> 本项目仅用于格式互操作研究、个人数据迁移与处理你合法取得且有权使用的音频。它不提供歌曲、会员权限、账号凭据或逐曲密钥，也不鼓励绕过付费、许可或访问控制。公开仓库前请完整阅读下方的“版权、商标与法律声明”。

## 功能

- 自动寻找 Windows 酷狗客户端的 `KGMusicV3.db`；
- 在内存中解密数据库，不把明文数据库写入磁盘；
- 按块处理 KGG，避免整首音频一次性载入内存；
- 解密结果若已是 MP3，则直接输出，避免二次有损编码；
- FLAC、OGG、WAV 等其他音频通过 FFmpeg 转为 320 kbps MP3；
- 先写临时文件，经 `ffprobe` 验证后再原子替换最终文件；
- 单曲失败不影响其余文件，支持 `--dry-run` 与 `--overwrite`。

## 环境要求

- Windows 10/11；
- Python 3.10 或更高版本；
- FFmpeg 与 ffprobe（Conda 可通过 `conda-forge` 安装）。

Windows 下的数据库 AES 解密默认调用系统自带 CNG，因此没有必需的 pip 依赖。若当前 Python 支持 `pycryptodome`，脚本也会自动优先使用它。

```powershell
conda create -n kgg-converter -c conda-forge python=3.12 ffmpeg
conda activate kgg-converter
python -m pip install -r .\Code\requirements.txt
```

## 使用

将你自己的 `.kgg` 文件放在仓库根目录，确保酷狗客户端已经播放过对应文件，使逐曲 eKey 已写入本机数据库。随后完全退出酷狗客户端（包括托盘进程），先检查：

```powershell
python .\Code\convert_kgg_to_mp3.py --dry-run
```

确认所有密钥匹配后执行转换：

```powershell
python .\Code\convert_kgg_to_mp3.py
```

默认输出目录为 `Code/Mp3_Output`。覆盖已有结果：

```powershell
python .\Code\convert_kgg_to_mp3.py --overwrite
```

指定其他输入、输出或数据库：

```powershell
python .\Code\convert_kgg_to_mp3.py `
  --db "$env:APPDATA\KuGou8\KGMusicV3.db" `
  --input "D:\Music\KugouMusic" `
  --output "D:\Music\KugouMusic\Code\Mp3_Output"
```

查看全部参数：

```powershell
python .\Code\convert_kgg_to_mp3.py --help
```

## 示例音频

仓库允许提交的唯一音频是 [`examples/original_demo.mp3`](examples/original_demo.mp3)。它由 [`examples/generate_demo.py`](examples/generate_demo.py) 从数学波形现场合成，不含第三方歌曲、录音或 KGG 数据，用来确认 MP3 播放链路正常。

重新生成示例：

```powershell
python .\examples\generate_demo.py
```

该示例音频在法律允许的最大范围内按 [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/deed.zh-hans) 提供。它不是 KGG 解密测试向量；端到端测试必须由使用者在本地提供自己有权处理的文件。

## 隐私和仓库安全

`.gitignore` 默认排除：

- `.kgg/.kgm/.kgma/.vpr` 等加密媒体；
- `KGMusicV3.db`、`kgg.key`、SQLite 数据库和备份；
- 除原创 CC0 示例外的所有常见音频格式；
- `Code/Mp3_Output`、临时文件、日志、虚拟环境和 IDE 配置。

不要在 Issue、PR、Release 或测试附件中上传以下内容：

- 商业歌曲、解密后的音频或加密缓存；
- `KGMusicV3.db`、逐曲 eKey 或其他密钥文件；
- 酷狗账号信息、Cookie、设备标识、私人路径或个人数据库。

`.gitignore` 只能防止尚未跟踪的文件被误加；提交前仍应运行 `git status --short` 和 `git diff --cached --stat` 人工核对。如果敏感材料曾进入 Git 历史，仅删除工作区文件是不够的，需要清理历史并撤销或更换相关凭据。

## 版权、商标与法律声明

1. 本仓库代码用于格式互操作、学习和个人备份场景，不构成法律意见，也不保证某一用途在你所在地区合法。
2. 你只能处理自己创作、已获明确授权、属于公版，或通过合法账号取得且当地法律允许转换的内容。下载权、播放权或会员资格不当然等于复制、转换、传播或公开发布权。
3. 不得使用本项目获取无权访问的作品、规避购买或订阅、批量传播受版权保护的录音、提供密钥服务，或从事任何侵犯版权、合同、技术措施或平台规则的活动。
4. MIT 许可证只覆盖本仓库原创代码，不授予任何第三方歌曲、录音、数据库、商标、客户端或服务的权利。
5. “酷狗”“KuGou”及相关名称和商标归其权利人所有。本项目与酷狗及其关联公司没有隶属、授权、认可或合作关系。
6. 维护者和贡献者不对滥用、数据损失、账号限制、合同争议、版权投诉或其他后果承担责任；如对公开发布或具体使用存在疑问，请咨询所在地的合格法律专业人士。

尤其不要把当前目录中的商业歌曲作为“示例”推送到 GitHub。免责声明不能代替版权方许可；GitHub 可依据知识产权政策处理涉嫌侵权内容。

## 开源许可与第三方说明

- 本仓库代码采用 [GNU GPL v3.0 only](LICENSE)，原因是实现过程参考并移植了 GPL-3.0 项目的相关代码结构。分发本项目或修改版时，请遵守 GPL 的源码和许可义务。
- `examples/original_demo.mp3` 不属于 GPL 程序代码，在法律允许的最大范围内单独按 CC0 1.0 提供。
- KGG/QMC2 格式兼容实现参考 GPL-3.0 的 [Kugo Music Converter](https://github.com/skxxxkx666/Kugo-Music-Converter)，其算法来源又包括 MIT 许可的 [Unlock Music CLI](https://git.unlock-music.dev/um/cli)。
- TEA 轮数行为与 Go 官方 [`x/crypto/tea`](https://github.com/golang/crypto/tree/master/tea) 保持兼容；该组件采用 BSD 风格许可。
- FFmpeg 是独立程序，受其自身许可证约束，本仓库不分发 FFmpeg 二进制。

完整归属说明见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。

Copyright © 2026 KGG to MP3 contributors.
