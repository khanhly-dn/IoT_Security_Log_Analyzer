# 🔍 IoT Security Log Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Flask-Web%20UI-black?style=for-the-badge&logo=flask" />
  <img src="https://img.shields.io/badge/Security-Log%20Analysis-red?style=for-the-badge&logo=shield" />
  <img src="https://img.shields.io/badge/Detection-7%20Strategies-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" />
</p>

<p align="center">
  Công cụ phân tích log bảo mật tự động, phát hiện <strong>IP bất thường</strong> từ các file log Apache, Nginx, Syslog và JSON.<br/>
  Hỗ trợ <strong>7 chiến lược phát hiện tấn công</strong> với giao diện Web Dashboard và CLI chuyên nghiệp.
</p>

---

## 📌 Giới thiệu

**IoT Security Log Analyzer** được xây dựng nhằm giải quyết bài toán **phân tích log bảo mật** trong các hệ thống IoT và máy chủ thực tế.

Mỗi ngày server ghi ra hàng chục nghìn dòng log — không ai có thể đọc thủ công. Công cụ này tự động đọc, phân tích và phát hiện các IP có hành vi bất thường như:

- 🔴 **Brute-force** SSH / đăng nhập
- 🔴 **DoS / DDoS** – flood request bất thường
- 🟠 **Path scanner** – dò quét đường dẫn nhạy cảm
- 🟠 **Error flood** – tỉ lệ lỗi 4xx/5xx cao bất thường
- 🟡 **Off-hours actor** – hoạt động ngoài giờ làm việc
- 🟡 **User-Agent rotation** – đổi danh tính để tránh bị phát hiện
- 🟡 **Burst attack** – flood trong cửa sổ 60 giây

---

## 🧩 Sơ đồ hoạt động

<p align="center">
  <img width="700" alt="Sơ đồ hoạt động" src="https://github.com/khanhly-dn/IoT_Security_Log_Analyzer/blob/main/SDHD.png?raw=true" />
</p>

---

## ⚙️ Chức năng chính

- **Đọc nhiều file log cùng lúc** – Apache, Nginx, Syslog, JSON, Generic
- **7 chiến lược phát hiện** tấn công tự động
- **Phân loại mức độ:** `CRITICAL` → `HIGH` → `MEDIUM` → `LOW`
- **Top Offenders** – xếp hạng IP nguy hiểm nhất theo Risk Score
- **Web Dashboard** – upload log, xem kết quả, lọc theo severity
- **CLI** – chạy nhanh trên terminal với nhiều tùy chọn
- **4 định dạng xuất báo cáo:** Terminal (màu ANSI), JSON, HTML, CSV
- **Whitelist IP** – bỏ qua các IP tin cậy
- **Tùy chỉnh ngưỡng** phát hiện theo nhu cầu

---

## 💻 Phần mềm & Công nghệ

- **Ngôn ngữ:** Python 3.11+
- **Web Framework:** Flask
- **Thư viện:** `re`, `json`, `csv`, `ipaddress`, `datetime`, `dataclasses` *(pure stdlib)*
- **Testing:** pytest – 27 unit tests
- **Giao diện:** Web App (HTML/CSS/JS) + CLI (argparse)
- **Không cần cài thư viện ngoài** – chỉ cần `flask` cho web UI

---

## 🌐 Giao diện Web Dashboard

<p align="center">
  <img width="700" alt="Giao diện Web" src="https://github.com/khanhly-dn/IoT_Security_Log_Analyzer/blob/main/GD.png?raw=true" />
</p>

---

## 📊 Kết quả phân tích

<p align="center">
  <img width="49%" alt="Kết quả 1" src="https://github.com/khanhly-dn/IoT_Security_Log_Analyzer/blob/main/KQ1.png?raw=true" />
  <img width="49%" alt="Kết quả 2" src="https://github.com/khanhly-dn/IoT_Security_Log_Analyzer/blob/main/KQ2.png?raw=true" />
</p>

---

## 📁 Cấu trúc dự án

```
IoT_Security_Log_Analyzer/
├── main.py                     # CLI entry point
├── app.py                      # Flask web server
├── generate_sample_logs.py     # Tạo log mẫu để test
├── requirements.txt
├── analyzer/
│   ├── __init__.py
│   ├── log_parser.py           # Parse Apache/Nginx/Syslog/JSON
│   ├── anomaly_detector.py     # 7 thuật toán phát hiện bất thường
│   └── reporter.py             # Xuất báo cáo Text/JSON/HTML/CSV
├── templates/
│   └── index.html              # Web Dashboard UI
├── tests/
│   └── test_analyzer.py        # 27 unit tests
└── sample_logs/
    ├── access.log              # Log mẫu Apache (4,333 dòng)
    └── syslog.log              # Log mẫu Syslog (585 dòng)
```

---

## 🔍 Chiến lược phát hiện

| Chiến lược | Mô tả | Mức độ |
|---|---|---|
| **High Frequency** | Vượt ngưỡng request/phút | CRITICAL / HIGH |
| **Burst** | Flood trong cửa sổ 60 giây | HIGH |
| **Auth Failure** | Đăng nhập thất bại liên tục | CRITICAL / HIGH |
| **Path Scan** | Dò quét nhiều đường dẫn nhạy cảm | CRITICAL / HIGH |
| **Error Rate** | Tỉ lệ lỗi 4xx/5xx bất thường | HIGH / MEDIUM |
| **Off Hours** | Hoạt động ngoài giờ làm việc | MEDIUM |
| **UA Churn** | Thay đổi User-Agent liên tục | MEDIUM |

---

## 🚀 Hướng dẫn cài đặt & chạy

**1. Clone repository**
```bash
git clone https://github.com/khanhly-dn/IoT_Security_Log_Analyzer.git
cd IoT_Security_Log_Analyzer
```

**2. Cài đặt thư viện**
```bash
pip install -r requirements.txt
```

**3. Tạo log mẫu để test**
```bash
python generate_sample_logs.py
```

**4a. Chạy Web Dashboard**
```bash
python app.py
# Mở trình duyệt: http://localhost:5000
```

**4b. Hoặc chạy CLI**
```bash
# Phân tích cơ bản
python main.py sample_logs/access.log sample_logs/syslog.log

# Chỉ hiện HIGH trở lên
python main.py sample_logs/access.log --severity HIGH

# Xuất báo cáo HTML
python main.py sample_logs/access.log --format html --output report.html

# Xuất báo cáo JSON
python main.py sample_logs/access.log --format json --output report.json
```

**5. Chạy tests**
```bash
python -m pytest tests/test_analyzer.py -v
```

---

## 📈 Tùy chỉnh ngưỡng phát hiện

```bash
python main.py access.log \
  --freq-threshold 200 \     # Ngưỡng request/phút
  --error-rate 0.5 \         # Ngưỡng tỉ lệ lỗi
  --scan-paths 100 \         # Ngưỡng số path khác nhau
  --auth-fail 10 \           # Ngưỡng auth failure
  --whitelist 8.8.8.8        # Bỏ qua IP tin cậy
```

---

## 🧪 Kết quả kiểm thử

```
27 passed in 0.18s
✓ TestLogParser        – 8 tests
✓ TestAnomalyDetector  – 12 tests
✓ TestReporters        – 6 tests
✓ TestIntegration      – 1 test
```
🎬 **Video hoạt động:** *https://drive.google.com/file/d/1erSd5t49KVjsgHNJW2jI553P84yq8pfP/view?usp=sharing*

---

## 🚀 Hướng phát triển

- [ ] Tích hợp **GeoIP** – hiển thị vị trí địa lý của IP bất thường
- [ ] **Real-time monitoring** – đọc log trực tiếp khi file thay đổi
- [ ] **Email / Telegram alert** – gửi cảnh báo tự động khi phát hiện CRITICAL
- [ ] **Machine Learning** – phát hiện bất thường dựa trên mô hình học
- [ ] **Docker support** – đóng gói và triển khai dễ dàng
- [ ] **Dashboard biểu đồ** – thống kê theo thời gian thực

---

## 👤 Thực hiện

**Lý Gia Khánh**  
Khoa Công nghệ Thông tin – Trường Đại học Đại Nam

---

<p align="center">
  Using Python · Flask · pytest
</p>
