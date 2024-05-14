# behind the scenes

![1](https://github.com/noobmannn/KCSC_CTF_2024/blob/0d7d091ea183b58f5fe85641243d14fcd4a475a0/behind%20the%20scenes/Img/1.png)

Challenge cho chúng ta một file exe ở dạng PE32

![2](https://github.com/noobmannn/KCSC_CTF_2024/blob/0d7d091ea183b58f5fe85641243d14fcd4a475a0/behind%20the%20scenes/Img/2.png)

Chạy thử file, chương trình yêu cầu nhập Flag, sai thì trả về ``wrong``

![3](https://github.com/noobmannn/KCSC_CTF_2024/blob/0d7d091ea183b58f5fe85641243d14fcd4a475a0/behind%20the%20scenes/Img/3.png)

Mở file bằng ida, xem hàm main của chương trình

![4](https://github.com/noobmannn/KCSC_CTF_2024/blob/0d7d091ea183b58f5fe85641243d14fcd4a475a0/behind%20the%20scenes/Img/4.png)

### Resolve API

Vào hàm ``sub_C32E80``, có thể thấy cách chương trình gọi API hơi lạ

![5](https://github.com/noobmannn/KCSC_CTF_2024/blob/0d7d091ea183b58f5fe85641243d14fcd4a475a0/behind%20the%20scenes/Img/5.png)

xref theo biến ``apicall2``, ta tới được hàm ``implement2``, sau đó đi tiếp vào hàm ``MyVtImplementation`` -> ``APICALL``, ta gặp được biến ``APICALL::`vftable'``

![6](https://github.com/noobmannn/KCSC_CTF_2024/blob/0d7d091ea183b58f5fe85641243d14fcd4a475a0/behind%20the%20scenes/Img/6.png)

Xem biến ``APICALL::`vftable'``, có thể thấy đây là một struct chứa địa chỉ của rất nhiều hàm khác nhau

![7](https://github.com/noobmannn/KCSC_CTF_2024/blob/0d7d091ea183b58f5fe85641243d14fcd4a475a0/behind%20the%20scenes/Img/7.png)

Xem qua tất cả các hàm, có thể thấy chúng đều có một cấu trúc chung giống như hàm ``sub_401220`` dưới đây

![8](https://github.com/noobmannn/KCSC_CTF_2024/blob/0d7d091ea183b58f5fe85641243d14fcd4a475a0/behind%20the%20scenes/Img/8.png)

Có thể thấy hàm trên truyền vào hai chuỗi hash, sau đó gọi hàm ``sub_402B80``, đọc qua code có thể thấy hàm này dùng PEB để ResolveAPI dựa vào 2 chuối hash được truyền vào

![9](https://github.com/noobmannn/KCSC_CTF_2024/blob/0d7d091ea183b58f5fe85641243d14fcd4a475a0/behind%20the%20scenes/Img/9.png)

Tổng kết lại có thể thấy các hàm trong ``APICALL::`vftable'`` đều có 1 cách hoạt động chung, sử dụng hai chuỗi hash được khai báo để Resolve API, sau đó call API vừa resolve được với tham số là các tham số truyền vào của các hàm trên.

``APICALL::`vftable'`` ban đầu có thể là một class C++ chứa địa chỉ các hàm resolve API, tuy nhiên vì ida không load được cấu trúc của class nên chúng ta thấy nó ở dạng ``vftable``. Sau đó ta thấy 1 số hàm sẽ được gọi dưới dạng câu lệnh ``apicall1 + 8``,... đó chính là câu lệnh ``apicall->GetProcAddr`` ở code gốc C++. Để thuận lợi cho việc đọc code và debug, mình sẽ SetIP và debug vào trước từng hàm để đổi tên chúng sang tên API mà hàm gọi ra.

![10](https://github.com/noobmannn/KCSC_CTF_2024/blob/0d7d091ea183b58f5fe85641243d14fcd4a475a0/behind%20the%20scenes/Img/10.png)

### Phân tích hàm main_handle

Sau khi gọi hàm ``sub_C32E80`` để load dll cần thiết và yêu cầu nhập Input, chương trình chạy đến hàm ``main_handle``. Có thể thấy hàm này bị obfuscate bằng cách chèn byte rác và chèn code rác vào chương trình

![11](https://github.com/noobmannn/KCSC_CTF_2024/blob/845ba24b603db4c0e76bd46a8a3215cf5cc9a2ca/behind%20the%20scenes/Img/11.png)

Nop đi byte và code rác, sau đó ấn P để Make Function, sau đó xem mã giả của hàm ``main_handle``

![12](https://github.com/noobmannn/KCSC_CTF_2024/blob/845ba24b603db4c0e76bd46a8a3215cf5cc9a2ca/behind%20the%20scenes/Img/12.png)

Có thể thấy tất cả các string quan trọng trong chương trình đều đã bị encrypt ở dạng Base64, và chỉ được decrypt bằng hàm ``decrypt_base64`` rồi mới sử dụng tiếp. Hàm ``main_handle`` đầu tiên lấy đường dẫn thư mục Temp trong máy, sau đó ghép nó với chuối ``Cachedata.bin``.  Cuối cùng đẩy toàn bộ đường dẫn trên vào biến Buffer. Sau đó chương trình gọi hàm ``readfilefromInternet``

![13](https://github.com/noobmannn/KCSC_CTF_2024/blob/845ba24b603db4c0e76bd46a8a3215cf5cc9a2ca/behind%20the%20scenes/Img/13.png)

Sau khi debug và phân tích, có thể thấy hàm ``readfilefromInternet`` tiến hành tải một file từ ``http://172.245.6.189:4444/test.txt`` sau đó viết nội dung file được tải vào file ``cachedata.bin``. Kết thúc quá trình trên, chương trình quay về hàm main, ghép đường dẫn thư mục Temp với chuỗi ``KCSC.dll`` sau đó gọi hàm ``decrypt_filedll``

![14](https://github.com/noobmannn/KCSC_CTF_2024/blob/845ba24b603db4c0e76bd46a8a3215cf5cc9a2ca/behind%20the%20scenes/Img/14.png)

Hàm này viết nội dung file ``cachedata.bin`` vào biến ``Block``, sau đó cho qua hai hàm ``rc4_ksa`` và ``rc4_prga`` để Decrypt data biến ``Block``, cuối cùng là ghi data của biến ``Block`` vào file ``KCSC.dll``.

![15](https://github.com/noobmannn/KCSC_CTF_2024/blob/845ba24b603db4c0e76bd46a8a3215cf5cc9a2ca/behind%20the%20scenes/Img/15.png)

Cuối cùng chương trình quay về hàm main, dùng ``LoadLibraryA`` để load ``KCSC.dll`` vào chương trình, sau đó dùng ``GetProcAddress`` để lấy địa chỉ hàm ``HelloWorld`` trong ``KCSC.dll``, cuối cùng dùng input nhập vào làm tham số và gọi hàm ``HelloWorld``, có vẻ đây chính là hàm encrpt và check flag. Nếu đúng thì chương trình in ra ``correct`` còn sai thì trả về ``wrong``.

