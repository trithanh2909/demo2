#!/usr/bin/env python3
"""Bản triển khai MD5 phục vụ học tập theo RFC 1321.

Cảnh báo: MD5 không còn an toàn cho các ứng dụng cần khả năng chống va chạm.
Chương trình này chỉ dùng để học thuật toán, kiểm thử và minh họa tính toàn vẹn.
Phần lõi md5() tự thực hiện thuật toán; hashlib chỉ được gọi trong self_test()
để đối chiếu kết quả, không dùng để tạo digest trong chức năng chính.
"""

from __future__ import annotations

import hashlib  # Chỉ dùng trong self_test(), không dùng trong lõi MD5.
import hmac
import math
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any


# ============================================================================
# PHẦN 1. HẰNG SỐ VÀ CÁC PHÉP TOÁN CƠ BẢN CỦA MD5
# ============================================================================

_MASK32 = 0xFFFFFFFF

# Lịch xoay trái: 4 vòng, mỗi vòng 16 bước.
_SHIFT = (
    [7, 12, 17, 22] * 4
    + [5, 9, 14, 20] * 4
    + [4, 11, 16, 23] * 4
    + [6, 10, 15, 21] * 4
)

# T[i] = floor(2^32 * abs(sin(i))), i = 1..64; góc tính theo radian.
_K = [int(abs(math.sin(i + 1)) * (1 << 32)) & _MASK32 for i in range(64)]

# Bốn từ trạng thái khởi tạo theo RFC 1321.
_INITIAL_STATE = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)


def _left_rotate(value: int, amount: int) -> int:
    """Xoay trái một giá trị trong phạm vi 32 bit."""
    value &= _MASK32
    return ((value << amount) | (value >> (32 - amount))) & _MASK32


def _pad(message: bytes) -> bytes:
    """Đệm thông điệp: bit 1, các bit 0, rồi độ dài ban đầu 64 bit little-endian."""
    original_length_bits = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    padded = bytearray(message)
    padded.append(0x80)

    while len(padded) % 64 != 56:
        padded.append(0)

    padded.extend(struct.pack("<Q", original_length_bits))
    return bytes(padded)

# ============================================================================
# PHẦN 2. LÕI MD5 — HÀM CHÍNH CỦA TOÀN BỘ CHƯƠNG TRÌNH
# ============================================================================


def md5(
    message: bytes,
    *,
    trace: bool = False,
) -> str | tuple[str, list[dict[str, Any]]]:
    """Tính MD5 của dữ liệu bytes.

    Args:
        message: Dữ liệu đầu vào dạng bytes hoặc kiểu bytes-like.
        trace: Nếu True, trả thêm trạng thái A/B/C/D sau từng bước biến đổi.

    Returns:
        Digest gồm 32 ký tự hex; hoặc (digest, trace_rows) khi trace=True.
    """
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("md5() cần bytes; hãy mã hóa văn bản bằng UTF-8 trước.")

    data = _pad(bytes(message))
    a0, b0, c0, d0 = _INITIAL_STATE
    trace_rows: list[dict[str, Any]] = []

    # Mỗi khối MD5 có 64 byte (512 bit).
    for block_index in range(0, len(data), 64):
        block = data[block_index:block_index + 64]
        words = struct.unpack("<16I", block)  # 16 từ 32 bit, little-endian.
        a, b, c, d = a0, b0, c0, d0

        # Mỗi khối trải qua 64 bước, chia thành 4 vòng.
        for i in range(64):
            if i < 16:
                function = (b & c) | ((~b) & d)
                word_index = i
                round_number = 1
            elif i < 32:
                function = (d & b) | ((~d) & c)
                word_index = (5 * i + 1) % 16
                round_number = 2
            elif i < 48:
                function = b ^ c ^ d
                word_index = (3 * i + 5) % 16
                round_number = 3
            else:
                function = c ^ (b | (~d))
                word_index = (7 * i) % 16
                round_number = 4

            # Cộng modulo 2^32, sau đó xoay trái theo lịch của vòng hiện tại.
            mixed = (a + function + _K[i] + words[word_index]) & _MASK32
            rotated = _left_rotate(mixed, _SHIFT[i])

            # Cập nhật bốn thanh ghi theo thứ tự quy định của MD5.
            old_b, old_c, old_d = b, c, d
            a = old_d
            b = (old_b + rotated) & _MASK32
            c = old_b
            d = old_c

            if trace:
                trace_rows.append(
                    {
                        "block": block_index // 64 + 1,
                        "step": i + 1,
                        "round": round_number,
                        "word_index": word_index,
                        "A": f"{a:08x}",
                        "B": f"{b:08x}",
                        "C": f"{c:08x}",
                        "D": f"{d:08x}",
                    }
                )

        # Feed-forward: cộng trạng thái làm việc vào trạng thái tích lũy.
        a0 = (a0 + a) & _MASK32
        b0 = (b0 + b) & _MASK32
        c0 = (c0 + c) & _MASK32
        d0 = (d0 + d) & _MASK32

    digest_bytes = struct.pack("<4I", a0, b0, c0, d0)
    digest = digest_bytes.hex()
    return (digest, trace_rows) if trace else digest


def md5_text(text: str) -> str:
    """Mã hóa chuỗi Unicode bằng UTF-8 rồi tính MD5."""
    return str(md5(text.encode("utf-8")))


# ============================================================================
# PHẦN 3. TÍNH MD5 CHO TỆP VÀ KIỂM TRA TÍNH TOÀN VẸN
# ============================================================================


def hash_file(path: str | Path) -> str:
    """Đọc tệp dạng bytes và trả về digest MD5.

    Bản demo này đọc toàn bộ tệp vào RAM, phù hợp với tệp mẫu/bài tập nhỏ.
    """
    file_path = Path(path).expanduser()
    data = file_path.read_bytes()
    return str(md5(data))


def verify_file(path: str | Path, expected_digest: str) -> tuple[bool, str]:
    """So sánh MD5 của tệp với digest tham chiếu đã được cung cấp.

    Hàm này chỉ so sánh hai digest. Nó không chứng minh nguồn gốc tệp và không
    bảo vệ trước đối thủ chủ động tạo va chạm MD5.
    """
    actual = hash_file(path)
    normalized = expected_digest.strip().lower()
    is_valid_digest = len(normalized) == 32 and all(
        char in "0123456789abcdef" for char in normalized
    )
    matched = is_valid_digest and hmac.compare_digest(actual, normalized)
    return matched, actual


# ============================================================================
# PHẦN 4. TỰ KIỂM THỬ — GIỮ TEST CƠ BẢN TRONG MAIN.PY
# ============================================================================


def self_test() -> bool:
    """Chạy test vector RFC 1321 và một số test biên/tính toàn vẹn."""
    vectors = [
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (b"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (b"1234567890" * 8, "57edf4a22be3c955ac49da2e2107b67a"),
    ]

    total = 0
    passed = 0

    def check(name: str, condition: bool) -> None:
        nonlocal total, passed
        total += 1
        if condition:
            passed += 1
            print(f"[PASS] {name}")
        else:
            print(f"[FAIL] {name}")

    print("\n========== TỰ KIỂM THỬ MD5 ==========")

    for index, (message, expected) in enumerate(vectors, start=1):
        check(f"RFC 1321 test vector {index}", md5(message) == expected)

    # Kiểm tra các ranh giới padding/khối bằng đối chiếu với hashlib.
    # hashlib chỉ xuất hiện trong phần test, không nằm trong lõi md5().
    boundary_ok = True
    for length in (0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1024):
        data = bytes(i % 256 for i in range(length))
        if md5(data) != hashlib.md5(data).hexdigest():
            boundary_ok = False
            break
    check("Độ dài biên padding và khối dữ liệu", boundary_ok)

    unicode_ok = md5_text("Xin chào Việt Nam") == hashlib.md5(
        "Xin chào Việt Nam".encode("utf-8")
    ).hexdigest()
    check("Văn bản tiếng Việt UTF-8", unicode_ok)

    try:
        md5("abc")  # type: ignore[arg-type]
        type_ok = False
    except TypeError:
        type_ok = True
    check("Từ chối đầu vào chuỗi chưa mã hóa thành bytes", type_ok)

    trace_result = md5(b"abc", trace=True)
    trace_ok = (
        isinstance(trace_result, tuple)
        and trace_result[0] == "900150983cd24fb0d6963f7d28e17f72"
        and len(trace_result[1]) == 64
    )
    check("Trace có đủ 64 bước cho khối abc", trace_ok)

    with tempfile.TemporaryDirectory() as directory:
        sample = Path(directory) / "sample.txt"
        sample.write_bytes(b"MD5 integrity test")
        original_digest = hash_file(sample)
        match_ok = verify_file(sample, original_digest.upper())[0]
        check("Tệp nguyên bản khớp digest tham chiếu", match_ok)

        sample.write_bytes(b"MD5 integrity test changed")
        mismatch_ok = not verify_file(sample, original_digest)[0]
        check("Tệp thay đổi không khớp digest cũ", mismatch_ok)

        invalid_ok = not verify_file(sample, "not-a-digest")[0]
        check("Từ chối digest sai định dạng", invalid_ok)

    print(f"\nKết quả: {passed}/{total} kiểm tra đạt.")
    print("OK" if passed == total else "CÓ KIỂM TRA THẤT BẠI")
    return passed == total


# ============================================================================
# PHẦN 5. GIAO DIỆN DÒNG LỆNH (CLI) ĐỂ DEMO TRÊN CMD
# ============================================================================


def ask_path() -> Path | None:
    raw = input("Nhập đường dẫn tệp (có thể kéo-thả tệp vào CMD): ").strip().strip('"')
    path = Path(raw).expanduser()
    if not path.is_file():
        print("Không tìm thấy tệp. Hãy kiểm tra đường dẫn rồi thử lại.")
        return None
    return path


def show_trace() -> None:
    digest, rows = md5(b"abc", trace=True)
    print("\nTrace MD5 cho thông điệp 'abc' (hiển thị 8 bước đầu).")
    print("Bước | Vòng | Chỉ số từ | A        | B        | C        | D")
    for row in rows[:8]:
        print(
            f"{row['step']:>4} | {row['round']:>4} | {row['word_index']:>9} | "
            f"{row['A']} | {row['B']} | {row['C']} | {row['D']}"
        )
    print(f"MD5('abc') = {digest}")


def menu() -> None:
    while True:
        print("\n========== DEMO HÀM BĂM MD5 ==========")
        print("1. Tính MD5 cho văn bản")
        print("2. Tính MD5 cho một tệp")
        print("3. Kiểm tra tính toàn vẹn của tệp")
        print("4. Hiển thị trace MD5('abc')")
        print("5. Chạy bộ tự kiểm thử")
        print("0. Thoát")
        choice = input("Chọn chức năng: ").strip()

        if choice == "1":
            text = input("Nhập văn bản: ")
            print(f"Độ dài UTF-8: {len(text.encode('utf-8'))} byte")
            print(f"MD5 = {md5_text(text)}")

        elif choice == "2":
            path = ask_path()
            if path:
                try:
                    print(f"Tệp: {path}")
                    print(f"Kích thước: {path.stat().st_size} byte")
                    print(f"MD5 = {hash_file(path)}")
                except OSError as error:
                    print(f"Không thể đọc tệp: {error}")

        elif choice == "3":
            path = ask_path()
            if path:
                expected = input("Nhập digest MD5 tham chiếu (32 ký tự hex): ").strip()
                try:
                    matched, actual = verify_file(path, expected)
                    print(f"MD5 tính được: {actual}")
                    print(
                        "KẾT QUẢ: KHỚP."
                        if matched
                        else "KẾT QUẢ: KHÔNG KHỚP hoặc digest tham chiếu không hợp lệ."
                    )
                    print("Lưu ý: MD5 không bảo đảm chống giả mạo trước đối thủ chủ động.")
                except OSError as error:
                    print(f"Không thể đọc tệp: {error}")

        elif choice == "4":
            show_trace()

        elif choice == "5":
            self_test()

        elif choice == "0":
            print("Kết thúc demo.")
            return

        else:
            print("Lựa chọn không hợp lệ. Hãy nhập 1, 2, 3, 4, 5 hoặc 0.")


def main() -> None:
    menu()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nĐã dừng chương trình.")
        sys.exit(130)
