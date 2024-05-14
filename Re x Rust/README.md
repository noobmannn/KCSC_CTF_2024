# Re x Rust

![7](https://github.com/noobmannn/KCSC_CTF_2024/blob/f117d74bba8d43b6d7e32b6d11de1cec6c96c981/Re%20x%20Rust/Img/7.png)

Challenge cho 1 file ``rexrust`` là file ELF64 và 1 file ``flag.enc``

![1](https://github.com/noobmannn/KCSC_CTF_2024/blob/f117d74bba8d43b6d7e32b6d11de1cec6c96c981/Re%20x%20Rust/Img/1.png)

Mở file bằng IDA, như tên gọi thì code Rust nhìn khá là khó đọc, nhưng nếu đọc kĩ thì có thể thấy chương trình đang mã hoá một file được truyền vào và được mã hoá qua 4 giai đoạn

![2](https://github.com/noobmannn/KCSC_CTF_2024/blob/f117d74bba8d43b6d7e32b6d11de1cec6c96c981/Re%20x%20Rust/Img/2.png)

### Phase 1

![3](https://github.com/noobmannn/KCSC_CTF_2024/blob/f117d74bba8d43b6d7e32b6d11de1cec6c96c981/Re%20x%20Rust/Img/3.png)

Đọc kĩ mã giả và debug, có thể dễ dàng nhận định phase này chỉ đơn giản là đảo ngược toàn bộ data của file lại.

```python
stri = stri[::-1]
```

### Phase 2

![4](https://github.com/noobmannn/KCSC_CTF_2024/blob/f117d74bba8d43b6d7e32b6d11de1cec6c96c981/Re%20x%20Rust/Img/4.png)

Phase này tiến hành swap byte hai phần tử liền kề nhau, vd: 0xab và 0xcd ==> 0xad và 0xcb, dựng lại bằng python trông sẽ như thế này

```python
def ph2(stri):
    for i in range(0, len(stri) - 1, 2):
        v4 = (stri[i] & 0xf) | (stri[i + 1] & 0xf0)
        stri[i] = (stri[i + 1] & 0xf) | (stri[i] & 0xf0)
        stri[i + 1] = v4
    return stri
```

Cấu trúc này có thể giữ nguyên cho cả hai việc encrypt và decrypt

### Phase 3

![5](https://github.com/noobmannn/KCSC_CTF_2024/blob/f117d74bba8d43b6d7e32b6d11de1cec6c96c981/Re%20x%20Rust/Img/5.png)

Dựng lại bằng python thì sẽ trông như thế này

```python
def ph3(stri):
    for i in range(0, len(stri) - 2, 1):
        stri[i] = (stri[i] - stri[i + 2]) & 0xFF
        stri[i+2] = (stri[i + 2] - stri[i]) & 0xFF
    return stri
```

### Phase 4

![6](https://github.com/noobmannn/KCSC_CTF_2024/blob/f117d74bba8d43b6d7e32b6d11de1cec6c96c981/Re%20x%20Rust/Img/6.png)

Dựng lại bằng python

```python
def ph4(stri):
    # v6 là một số 4 byte được random bất kỳ
    for i in range(len(stri)):
        stri[i] ^= (((v6 >> 24) & 0xff) ^ ((v6 >> 16) & 0xff) ^ (
            (v6 >> 8) & 0xff) ^ (v6 & 0xff))
    return stri
```

Chương trình random 1 số bốn byte, sau đó xor từng byte 1 của số đó lại với nhau, khi đó ta được 1 số 1 byte, và số 1 byte này mang đi xor tiếp với từng kí tự của data

Vì suy cho cùng chỉ là xor hai số 1 byte lại với nhau nên hoàn toàn có thể Bruteforce từ 0 đến 0xFF

### Decrypt

Dưới đây là script giải để tìm flag

```python
def ph1(stri):
    return stri[::-1]

def ph2(stri):
    for i in range(0, len(stri) - 1, 2):
        v4 = (stri[i] & 0xf) | (stri[i + 1] & 0xf0)
        stri[i] = (stri[i + 1] & 0xf) | (stri[i] & 0xf0)
        stri[i + 1] = v4
    return stri

# def ph3(stri):
#     for i in range(0, len(stri) - 2, 1):
#         stri[i] = (stri[i] - stri[i + 2]) & 0xFF
#         stri[i+2] = (stri[i + 2] - stri[i]) & 0xFF
#     return stri

def ph3(stri):
    for i in range(len(stri) - 1, 1, -1):
        stri[i] = (stri[i] + stri[i - 2]) & 0xFF
        stri[i-2] = (stri[i - 2] + stri[i]) & 0xFF
    return stri

# def ph4(stri):
#     # v6 = rand 
#     for i in range(len(stri)):
#         stri[i] ^= (((v6 >> 24) & 0xff) ^ ((v6 >> 16) & 0xff) ^ (
#             (v6 >> 8) & 0xff) ^ (v6 & 0xff))
#     return stri

def ph4(stri, a):
    for i in range(len(stri)):
        stri[i] ^= a
    return stri

for i in range(0xFF):
    with open('flag.enc', 'rb') as file:
        data = file.read()
    enc = []
    for c in data:
        enc.append(c)
    enc = ph4(enc, i)
    enc = ph3(enc)
    enc = ph2(enc)
    enc = enc[::-1]
    flag = ''
    for j in range(len(enc)):
        flag += chr(enc[j])
    if 'KCSC{' in flag:
        print(hex(i))
        print(flag)
        break
```

Kết quả của script trên là chuỗi ``KCSC{r3v3rs3_rust_1s_funny_4nd_34sy_227da29931351}``, đây chính là flag của Challenge

# Flag

``KCSC{r3v3rs3_rust_1s_funny_4nd_34sy_227da29931351}``
