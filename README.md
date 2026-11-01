# Flama Media (Go)

Go trên **Worker 212** nhận và xử lý ảnh/audio/ZIP. Media được lưu lâu dài trên
212. Go cũng sinh SVG stroke và gửi qua VPN tới receiver trên **OV**; OV chỉ lưu
SVG stroke, không nhận media upload thông thường.

## Upload và lưu thẻ

1. Frontend xin HMAC ticket tại `POST /api/media/upload-ticket` của Flask.
2. Frontend gửi byte trực tiếp tới cổng media, proxy sang Go trên 212. Flask
   không nhận multipart của luồng trực tiếp này.
3. Go kiểm tra ticket, giới hạn byte/pixel, giải mã và re-encode ảnh, resize giữ
   tỉ lệ tối đa 1600px. JPEG/PNG/GIF/WebP được đọc; WebP được ghi thành PNG.
   ZIP có giới hạn entry/tổng giải nén/tỉ lệ nén và chặn đường dẫn không an toàn.
4. Go ghi staging có tên ngẫu nhiên, trả `/media/staged/stg_<id>` để preview.
5. Khi người dùng lưu thẻ, Flask xác thực quyền sửa, kiểm tra metadata/quota,
   cấp UUID `MediaAsset`, rồi gửi commit nội bộ qua VPN. Go xác thực chủ stage,
   chuyển file bằng **atomic rename** sang CAS và tạo alias UUID để các URL thẻ
   `/store/<MediaAsset UUID>` tiếp tục hoạt động.

Commit không đọc lại hoặc copy payload. Staging nằm cùng filesystem với CAS;
nếu cấu hình mount sai, rename thất bại thay vì ngầm copy. Cùng nội dung được
deduplicate theo SHA-256; một stage có thể phục vụ nhiều alias. Retry commit
cùng nội dung an toàn, kể cả sau restart giữa rename và ghi receipt.

```text
MEDIA_STORAGE_ROOT/
  staging/stg_<32 hex>/payload.<ext>
  staging/stg_<32 hex>/metadata.json
  ab/cd/<sha256>.<ext>                 # CAS lâu dài
  aliases/<2 chars>/<uuid>.json       # UUID -> CAS
```

## Ubuntu quản lý file tạm

Stage có hiệu lực **24 giờ** (`MEDIA_STAGE_TTL_SECONDS=86400`). API từ chối stage
hết hạn ngay cả khi file chưa được Ubuntu dọn. **Không có goroutine/janitor dọn
staging trong Go.** `systemd-tmpfiles` trên host chịu trách nhiệm xóa stage quá
1 ngày; việc xóa diễn ra ở lượt chạy timer kế tiếp.

Các thao tác stage giữ BSD `flock` trên thư mục stage để `systemd-tmpfiles` bỏ qua
thư mục đang được dùng. Preview mở FD trước khi nhả lock; Linux giữ byte sống
đến khi response đóng FD. File CAS và alias nằm ngoài cây được dọn.

Phải cấu hình tmpfiles/timer trên Ubuntu, kể cả khi chạy Go trong container với
bind mount. Mẫu generic (thay đường dẫn/user cho đúng host):

```text
# /etc/tmpfiles.d/flama-media.conf
e /data/flama/media/staging 0750 flama flama 1d -
```

Không dựa vào chính sách mặc định của `/tmp`: thời hạn và filesystem có thể khác
host. Cấu hình production thật được quản lý trong private `infra-vpn/flama/`.

## HTTP contract

| Endpoint | Xác thực | Kết quả |
| --- | --- | --- |
| `POST /media/upload` | Bearer HMAC `action=upload`, user ID dương | Một stage |
| `POST /media/upload-zip` | Cùng ticket upload | Danh sách stage và lỗi từng entry |
| `GET/HEAD /media/staged/<stage_id>` | Qua gateway; URL ngẫu nhiên | Preview `private, no-store` trong 24h |
| `POST /media/staged/inspect` | `X-Internal-Secret` | Metadata tin cậy của stage thuộc user |
| `POST /media/commit` | `X-Internal-Secret` | Rename vào CAS, tạo alias, trả receipt |
| `POST /media/assets/inspect` | `X-Internal-Secret` | Kiểm tra tồn tại/kích thước các alias |
| `GET/HEAD /store/<id>` | Qua gateway | Media CAS/alias UUID/UUID legacy |
| `GET /health` | Không yêu cầu ticket | Health/version |

Inspect body: `{"user_id":42,"stage_ids":["stg_<32 hex>"]}`.
Commit body: `{"user_id":42,"items":[{"stage_id":"stg_<32 hex>","asset_id":"<UUID>"}]}`.
Hai endpoint trả `{"items":[...]}` với `stage_id`, `asset_id`, `sha256`,
`size_bytes`, `content_type`, `relative_path`, `filename`, `width`, `height`,
`expires_at`. Permanent inspect nhận `{"asset_ids":["<UUID>"]}` và trả
`{"items":[{"asset_id":"<UUID>","exists":true,"size_bytes":123}]}`.

Public request phải qua gateway với `X-Flama-Gateway-Secret`. Internal routes
dùng secret riêng và được gọi trực tiếp qua VPN. Không đưa internal secret hoặc
gateway secret vào frontend. CORS chỉ cho phép origin khai báo rõ trong
`ALLOWED_ORIGINS`; upload không cần cookie của Flask.

## SVG stroke

`STROKE_ROLE=worker` trên 212 mở `POST /internal/strokes/generate`; worker đọc
dataset canonical, sinh SVG và `PUT` tới `STROKE_STORE_URL` trên OV.
`STROKE_ROLE=receiver` trên OV chỉ mở health và các route stroke nội bộ; không
khởi tạo kho media hoặc các route upload/store. Public SVG được Nginx OV phục vụ.

`STROKE_STORE_URL` phải gồm `/internal/strokes`, ví dụ
`http://wg-gateway:4793/internal/strokes`. Secret worker gửi sang OV phải khớp
`INTERNAL_SECURITY_SECRET` của receiver. Xem [stroke attribution](internal/stroke/THIRD_PARTY.md) cho
nguồn/license của dữ liệu stroke.

## Chạy và kiểm tra

Build bằng Go **1.27.3+** và `golang.org/x/image v0.47.0` đã có các bản sửa lỗi
WebP/VP8L. Không hạ dependency để chạy bằng Go cũ trên host; có thể dùng scoped
Go toolchain download khi build mà không thay `/usr/bin/go`.
Các bản sửa có trong [Go release history](https://go.dev/doc/devel/release),
[WebP decoder advisory](https://pkg.go.dev/vuln/GO-2026-5061) và
[VP8L memory advisory](https://pkg.go.dev/vuln/GO-2026-6222).

Copy `.env.example`, điền secret riêng và truyền các biến vào process. Binary
không tự đọc `.env`; Docker Compose có thể dùng file này để nội suy environment.
Mặc định `LISTEN_HOST=127.0.0.1`. Production đặt địa chỉ VPN của host; trong
container đặt `LISTEN_HOST=0.0.0.0`, chỉ publish cổng lên interface được phép.

```bash
go test ./...
go vet ./...
go test -race ./...
go build -o flama-media ./cmd/server
docker compose up --build
```

Startup từ chối thiếu HMAC/gateway/internal secret hoặc CORS wildcard. Receiver
không yêu cầu HMAC/gateway secret vì không nhận public upload.
