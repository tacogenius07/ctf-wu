# [Tên giải đấu] - [Tên Challenge]

**Category:** Web / Pwn / Crypto / Forensics  
**Difficulty:** Dễ / Trung bình / Khó  
**Author:** [Tên/Nickname của bạn]

## 1. Mô tả đề bài (Description)
[Tóm tắt ngắn gọn yêu cầu của đề bài hoặc dán trực tiếp mô tả từ ban tổ chức. Nếu có file đính kèm hoặc source code, hãy nhắc đến ở đây.]

## 2. Phân tích ban đầu (Information Gathering / Recon)
[Bạn đã làm gì đầu tiên khi nhận đề? 
Ví dụ: Quét Nmap, đọc source code, dùng Burp Suite chặn request, v.v. Chèn hình ảnh minh họa nếu cần.]

## 3. Quá trình giải quyết (Exploitation / Solution)
[Đây là phần quan trọng nhất. Hãy viết từng bước một theo tư duy logic của bạn.]
* **Bước 1:** Phát hiện lỗ hổng X ở tham số Y.
* **Bước 2:** Thử nghiệm payload đơn giản `...` nhưng bị filter.
* **Bước 3:** Bypass filter bằng cách sử dụng kỹ thuật Z.

**Đoạn code/Payload đã sử dụng:**
```python
import requests

url = "[http://example.com/api](http://example.com/api)"
payload = {"inject": "1' OR '1'='1"}
r = requests.post(url, data=payload)
print(r.text)
