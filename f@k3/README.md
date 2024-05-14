# f@k3

![1](https://github.com/noobmannn/KCSC_CTF_2024/blob/23907bc7968930c0d424a884c73e17832a4c7c23/f%40k3/Img/1.png)

Challenge cho chúng ta một file exe dạng PE64

![2](https://github.com/noobmannn/KCSC_CTF_2024/blob/23907bc7968930c0d424a884c73e17832a4c7c23/f%40k3/Img/2.png)

Chạy thử file với flag bừa thì kết quả in ra là ``Correct!``???

![3](https://github.com/noobmannn/KCSC_CTF_2024/blob/23907bc7968930c0d424a884c73e17832a4c7c23/f%40k3/Img/3.png)

Mở file bằng IDA và đọc qua hàm main, chương trình có vẻ đang thực hiện mã hoá RC4 với hai hàm ksa và prga lần lượt ở góc trên và dưới bên phải của hình dưới đây, key là chuỗi ``F@**!``

![4](https://github.com/noobmannn/KCSC_CTF_2024/blob/23907bc7968930c0d424a884c73e17832a4c7c23/f%40k3/Img/4.png)

Tuy nhiên điều kì lạ là chương trình không sử dụng Input nhập vào để mã hoá mà dùng mảng ```Str``` được khai báo ở trên. Tiến hành debug chương trình với breakpoint ở sau hàm prga. Khi này kết quả thuật toán RC4 là chuỗi ``KCSC{Could_be_a_f*k*_flag!}`` (chắc chắn là fake flag), và chuỗi này sẽ so sánh với input nhập vào bằng hàm ``lstrcmpA``. Tuy nhiên kết quả trả về luôn là ``Correct!``. Vậy thì chắc chắn hàm ``lstrcmpA`` có vấn đề.

Xem lại các hàm của chương trình, ta thấy có hàm ``sub_7FF61CA51490`` với nội dung như dưới đây, về cơ bản hàm này chạy trước hàm main và thực hiện thay đổi địa chỉ của hàm ``lstrcmpA`` thành địa chỉ hàm ``sub_7FF61CA51230``

![5](https://github.com/noobmannn/KCSC_CTF_2024/blob/23907bc7968930c0d424a884c73e17832a4c7c23/f%40k3/Img/5.png)

Đọc qua nội dung của hàm ``sub_7FF61CA51230`` ở dưới, có thể thấy chương trình xor chuỗi ``KCSC{Could_be_a_f*k*_flag!}`` với ```Str``` được định nghĩa trong hàm. Việc hàm này return 0 cũng giải thích tại sao chương trình luôn chạy vào luồng in chuỗi ``Correct!``. 

![6](https://github.com/noobmannn/KCSC_CTF_2024/blob/23907bc7968930c0d424a884c73e17832a4c7c23/f%40k3/Img/6.png)

Tuy nhiên nếu thực hiện Xor hai chuỗi như trên thì chỉ ra được Byte rác. Vậy ắt hẳn chương trình vẫn còn uẩn khúc nào đó???

Để ý kĩ các hàm của chương trình ta thấy có hàm ``sub_7FF61CA513D0`` với mục đích là thay đổi giá trị key được truyền vào trong các hàm mã hoá RC4 của hàm main (biến ``Str``)

![7](https://github.com/noobmannn/KCSC_CTF_2024/blob/23907bc7968930c0d424a884c73e17832a4c7c23/f%40k3/Img/7.png)

Mình sẽ viết script để mô phỏng lại thuật toán của hàm trên và patch kết quả vào biến ``Str``

```python
from os import *

c = 'F@**!'
enc = []
enc.append(ord(c[0]))
enc.append(ord(c[1])|1)
enc.append(ord(c[2])|1)
enc.append(ord(c[3])|1)
enc.append(ord(c[4])|1)
for i in range(5):
    idc.patch_byte(0x00007FF61CA55074+i, enc[i])
```

![8](https://github.com/noobmannn/KCSC_CTF_2024/blob/23907bc7968930c0d424a884c73e17832a4c7c23/f%40k3/Img/8.png)

Sau khi patch byte, tiếp tục debug qua các hàm mã hoá RC4 và hàm ``sub_7FF61CA51230``, ta lấy được flag của challange

![9](https://github.com/noobmannn/KCSC_CTF_2024/blob/23907bc7968930c0d424a884c73e17832a4c7c23/f%40k3/Img/9.png)

# Flag

```KCSC{1t_co5ld_be_right7_fla9_here_^.^@@}```


