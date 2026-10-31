# Flama Media Service (Go)

Dịch vụ chuyên biệt xử lý, lưu trữ và phát Media (Âm thanh `.mp3` & Hình ảnh Flashcard) cho nền tảng Flama.

Được thiết kế theo nguyên tắc **Zero-Trust & Hardened Security**:
- **Không tiếp xúc trực tiếp với Internet**: Toàn bộ request từ người dùng phải đi qua Cổng chính (OV Gateway / VPS Nginx). Máy 212 đóng vai trò Private Worker Node.
- **Xác thực qua HMAC Presigned Ticket**: Chỉ người dùng hợp lệ được Flama cấp vé ký số mới có thể upload.
- **Tẩy uế dữ liệu (Re-encoding)**: Giải mã pixel và vẽ lại ảnh mới (Pure Go) để triệt tiêu 100% mã độc EXIF/Polyglot.
- **Chống Decompression Bomb**: Kiểm tra kích thước và giới hạn pixel trước khi phân bổ RAM.
- **Ngăn chặn Path Traversal**: Lưu file dưới dạng UUIDv4 ngẫu nhiên, phân mảnh thư mục `ab/cd/<uuid>.<ext>`.

---

## 1. Kiến trúc phân luồng Mạng (OV Gateway -> 212)

```text
[ Internet / Client ]
         │
         │ 1. Toàn bộ traffic đi vào OV (VPS Chính)
         ▼
┌─────────────────────────────────┐
│        OV GATEWAY (VPS)         │
│  - Nginx Reverse Proxy          │
│  - Chặn spam / Giới hạn IP      │
│  - Thêm header:                 │
│    X-Flama-Gateway-Secret       │
└────────────────┬────────────────┘
                 │
                 │ 2. Proxy nội bộ sang 212 (Port 4792)
                 │    (Firewall 212 chỉ mở cho IP của OV)
                 ▼
┌─────────────────────────────────┐
│       MÁY CHỦ 212 (WORKER)      │
│  - Flama Media Service (Go)     │
│  - Lưu trữ ổ cứng /data/media   │
│  - ĐÓNG CỔNG VỚI TOÀN INTERNET  │
└─────────────────────────────────┘
```

---

## 2. Cấu hình Nginx trên OV Gateway (VPS Chính)

Thêm cấu hình sau vào `/etc/nginx/sites-available/flama`:

```nginx
# Định nghĩa upstream trỏ sang Máy 212
upstream flama_media_212 {
    server <IP_MAY_212>:4792;
    keepalive 32;
}

server {
    server_name flama.yourdomain.com;
    
    # 1. Phát file Audio / Ảnh Flashcard
    location /media/proxy/ {
        proxy_pass http://flama_media_212;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Flama-Gateway-Secret "flama-internal-gateway-secret-from-ov-to-212";

        # Cache tĩnh media tại Nginx
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }

    # 2. Upload file Media
    location /media/upload {
        proxy_pass http://flama_media_212;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Flama-Gateway-Secret "flama-internal-gateway-secret-from-ov-to-212";

        # Giới hạn kích thước upload tại Nginx
        client_max_body_size 25M;
        proxy_read_timeout 60s;
    }
}
```

---

## 3. Cấu hình Tường lửa (Firewall) trên Máy 212

Trên **Máy 212**, tuyệt đối không mở port 4792 ra Internet:
```bash
# Chỉ cho phép IP của OV Gateway kết nối vào cổng 4792
sudo ufw allow from <IP_OV_GATEWAY> to any port 4792 proto tcp comment "Allow OV Gateway only"
sudo ufw reload
```

---

## 4. Hướng dẫn Liên kết Git Submodule

Thư mục này hiện đã được khởi tạo Git độc lập cục bộ. Khi bạn đã tạo repository mới trên GitHub (ví dụ `https://github.com/TrinhChung/flama-media.git`):

### Bước 1: Push code `flama-media` lên repo riêng
```bash
cd flama-media
git remote add origin https://github.com/TrinhChung/flama-media.git
git branch -M main
git push -u origin main
```

### Bước 2: Đăng ký thành Submodule trong dự án Flama chính
Quay trở lại thư mục gốc của Flama (`nihongo`):
```bash
cd ..
git submodule add https://github.com/TrinhChung/flama-media.git flama-media
git commit -m "feat(infra): add flama-media as git submodule"
```
