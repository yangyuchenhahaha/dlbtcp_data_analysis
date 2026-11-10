# DLBTCP Data Analysis

TCP 数据预处理、端点连接统计、窗口负载分析和 TCP 事件分类源码。
仓库保留 Python、Shell、C/C++ 源码及已有的合成测试；数据、分析结果、图表、结论、编译产物和本地依赖包不随源码提交。

## 环境

- Linux、Bash、Python 3.12（原工作区版本）。
- Python 依赖记录在 `scripts/requirements-recovered.txt`，来自原工作区；安装时需要相应版本的软件源。
- C 工具需要 GCC 和 libpcap 开发包；`prepare_mawi_inputs.py` 需要 G++、GNU sort 和 gzip。
- `phase1_inspect.sh` 还需要 tshark、capinfos；中文绘图需要本机中文字体。

在仓库根目录安装 Python 依赖：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

编译所需的抓包工具：

```bash
gcc -O2 -o scripts/pcap2tsv scripts/pcap2tsv.c -lpcap
gcc -O2 -o scripts/pcap2tsv_checked scripts/pcap2tsv_checked.c -lpcap
gcc -O2 -o scripts/pcap_inventory scripts/pcap_inventory.c -lpcap
gcc -O2 -o scripts/pcap_extract_tcp scripts/pcap_extract_tcp.c -lpcap
```

`prepare_mawi_inputs.py` 会自行编译同目录的 C++ 辅助程序。

## 工具入口

| 用途 | 主要脚本 |
| --- | --- |
| 抓包检查与转换 | `phase1_inspect.sh`、`pcap2tsv.c`、`pcap2tsv_checked.c`、`pcap_inventory.c`、`pcap_extract_tcp.c` |
| CSV / MAWI 输入预处理 | `fbcsv2tsv.py`、`prepare_mawi_inputs.py`、`prepare_mawi_inputs.cpp` |
| 第一阶段与辅助数据分析 | `phase1_endpoint_summary.py`、`phase1_dctcp_dataset.py`、`rebuild_dctcp_clean.py`、`analyze_auxiliary_datasets.py` |
| 第二阶段连接与窗口统计 | `phase2_connection_totals.py`、`phase2_endpoint_windows.py`、`run_phase2_mawi.sh` |
| 窗口粒度比较 | `compare_phase2_window_granularity.py`、`run_phase2_granularity_comparison.sh` |
| 第三阶段 TCP 事件分类 | `phase3_tcp_events.py`、`summarize_phase3.py`、`run_phase3_mawi.sh` |
| 校验与数据指纹 | `validate_capture_parsers.py`、`validate_phase3_outputs.py`、`build_*_manifest.py` |
| 绘图与报告生成源码 | `plot_*.py`、`phase1_dctcp_figs.py`、`report_phase3.py` |

命令在仓库根目录执行。示例（输入文件需要自行准备）：

```bash
mkdir -p report
./scripts/pcap2tsv -u data/new/trace.pcap > report/new.tsv
python3 scripts/phase1_endpoint_summary.py report/new.tsv --out report/new_summary.json
```

分阶段运行脚本保留原实验的端点、时间窗口及文件名配置。使用新数据时需调整相应参数。
`run_phase2_mawi.sh` 依赖 `data/mawi/` 下的输入以及已有的数据来源记录，
`run_phase3_mawi.sh` 还依赖第二阶段窗口统计及来源记录；仅克隆源码不足以直接重跑完整实验。
`build_data_manifest.py` 和部分阶段清单脚本保留原实验的路径与固定校验值，复用到其他数据前需相应修改。
各 Python 工具的参数可查看源码或运行 `python3 scripts/<脚本名>.py --help`（以支持参数的脚本为准）。

## 合成测试

以下已有测试使用合成数据，无需下载实验数据；输入预处理测试会编译 C++ 辅助程序。

```bash
python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/summarize_phase3.py --self-test
python3 scripts/phase3_frontier_sensitivity.py --self-test
```

`.gitignore` 使用源码白名单，运行时产生的 `data/`、`report/`、图表、二进制及本地环境不会被 Git 自动加入。
