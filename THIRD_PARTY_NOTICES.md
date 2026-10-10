# Third-party notices

本项目的许可证见根目录 [`LICENSE`](LICENSE)。以下说明用于保留来源和许可信息，不改变各第三方组件各自的许可条款。

## Kugo Music Converter

- 项目：https://github.com/skxxxkx666/Kugo-Music-Converter
- 许可证：GNU General Public License v3.0
- 用途：KGG/KGM v5 文件头、`KGMusicV3.db` 页解密、eKey 派生和 QMC2 MAP/RC4 兼容实现的主要参考与移植来源。

因此，本仓库程序代码采用 `GPL-3.0-only` 分发。

## Unlock Music CLI

- 项目：https://git.unlock-music.dev/um/cli
- Go 模块：https://pkg.go.dev/unlock-music.dev/cli
- 许可证：MIT
- 用途：KGG/KGM、酷狗 PC 数据库及 QMC2 算法的上游格式研究来源。

## Go supplementary cryptography libraries

- 项目：https://github.com/golang/crypto
- 目录：`tea`
- 许可证：BSD-3-Clause
- 用途：用于确认 `NewCipherWithRounds(key, 32)` 的轮数语义与 TEA 兼容行为。本仓库是 Python 实现，不包含 Go 二进制或 Go 模块副本。

## FFmpeg

- 项目：https://ffmpeg.org/
- 许可证：取决于具体构建配置，可能为 LGPL 或 GPL
- 用途：作为用户环境中的独立外部程序，将解密后的非 MP3 音频转码为 MP3，并通过 ffprobe 校验结果。

本仓库不分发 FFmpeg 二进制。使用者应检查自己安装的 FFmpeg 构建及其对应许可。

## 商标与内容

“酷狗”“KuGou”以及其他第三方产品名称仅用于说明兼容性，相关商标归各自权利人所有。第三方歌曲、录音、客户端数据库、账号凭据和逐曲密钥不属于本项目，也不得随本仓库分发。
