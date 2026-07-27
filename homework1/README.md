# 作业1：比特币测试网交易与区块逐比特解析

## 团队成员

- 总负责人：袁观道（202300460146）
- 协助成员：周一鸣（202300460138）
- 协助成员：丁鹤洋（202300460173）

---

## 文件说明

| 文件 | 说明 |
|------|------|
| `report.pdf` | 实验报告（15页） |
| `report.tex` | 实验报告 LaTeX 源文件 |
| `cover.png` | 报告封面图片 |
| `1.png` | 生成测试网地址截图 |
| `2.png` | 交易广播确认截图 |
| `3-1.png ~ 3-7.png` | 交易逐字节解析截图 |
| `4.png` | 逐比特位分析截图 |
| `5.png` | 区块头解析截图 |
| `btc_parser_main.py` | 核心解析脚本（交易/区块/比特级） |
| `fetch_data.py` | 测试网数据获取脚本 |
| `send_tx.py` | 交易构造与发送脚本 |
| `my_tx_raw_hex.txt` | 发送的交易原始十六进制数据 |
| `my_tx_parse_output.txt` | 交易逐字节解析完整输出 |
| `tx_result.json` | 交易结果（TXID等） |
| `wallet_testnet.json` | 测试网钱包信息 |
| `block_info.json` | 区块元数据 |

---

## 运行说明

### 环境要求
- Python 3.12+
- 依赖库：`bitcoinlib`, `requests`

### 获取测试网数据
```bash
python fetch_data.py
```

### 逐字节解析交易
```bash
python btc_parser_main.py tx-file my_tx_raw_hex.txt
```

### 逐字节解析区块
```bash
python btc_parser_main.py block-file block_raw_hex.txt
```

### 比特级分析
```bash
python -c "from btc_parser_main import show_bit_analysis; show_bit_analysis(open('my_tx_raw_hex.txt').read().strip(),'My TX')"
```

---

## 实验概述

在比特币测试网上完成了交易的完整生命周期：
1. 生成测试网地址并获取测试币
2. 构造传统 P2PKH 交易并广播（TXID: `01afad94...490c32f0`）
3. 对交易原始数据逐字节、逐比特解析
4. 解析测试网区块头结构

交易详情：
- 发送方：`mzcQbD1arHqyBy66wQxQqERRYAdFkhQN3c`
- 接收方：`mvhYS76rbgg9pAnxxM2NbXjz19PGBydyQv`
- 金额：127,516 satoshis
- 手续费：300 satoshis
