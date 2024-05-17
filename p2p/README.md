# p2p

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/ac76aeda-489c-44d6-9219-51022198feda)

Đề cho chúng ta một file PE32

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/8f298b06-e3f0-4425-a100-f2383fa035bd)

Run file, chương trình yêu cầu nhập Flag, sai thì trả về ``Flag is incorrect!``

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/b99e9538-ef6a-4dcc-a341-462d4b24d23c)

Mở file bằng IDA, có thể thấy các string quan trọng đều đã bị encrypt, thực hiện debug để lấy lại string và resolve các API cần thiết, mình nhận thấy chương trình yêu cầu nhập flag, sau đó gọi hàm WriteFile và ReadFile một cách khá kì lạ

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/facf3551-acbc-4fe0-8e7e-e68c1bd62da8)

Sau khi debug kĩ và phân tích, mình nhận thấy có một số hàm được chạy trước hàm main, luồng cụ thể như sau: ``handle1`` -> ``handle2`` -> ``main``

Mình sẽ tiến hành phân tích từng hàm một.

### handle1 function

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/143fb647-43fc-4b25-ad35-cad3bed5c332)

Hàm này giữa quá trình decrypt các chuỗi, nó lại tiếp tục gọi đến hàm ``createPEFileandInjectItTocmdexe``

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/8de8cba8-8832-4f0f-bda0-7a08a29b14dd)

Hàm ``createPEFileandInjectItTocmdexe`` sau khi decrypt các string và resolve api, nó gọi hàm ``CreateProcessW`` để tạo một tiến trình cmd.exe. Sau đó qua thêm một vài bước tiền xử lý rồi gọi tiếp đến hàm ``returnPEFile``.

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/72c15e99-df4e-488b-80df-4e3594a22358)

Hàm ``returnPEFile`` sau khi decrypt các string và resolve api, hàm này gọi các hàm tương tác với resource trong file mixture.exe (FileResourceW, LoadResource, SizeofResource, LockResource). Tiến hành debug, mình thấy chương trình đang cố gắng lấy resource từ phần gọi là pfe của file mixture.exe. Mình thử mở file bằng CFF Explorer và vào phần Resource Editor, vào phần PFE bạn sẽ thấy những byte như dưới đây

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/1231cc8d-ebe8-47a6-b2f9-dfa2753a0659)

Trace qua toàn bộ phần xử lý resource và xem giá trị của biên ``v13``, ta sẽ thấy những byte trong resource trên được load vào chương trình

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/3a7f18c8-2144-475d-8b11-807335e7c7c8)

Cuối cùng sau 1 số hàm biến đổi, resource của chúng ta sẽ ở dạng file PE như dưới đây, kết thúc hàm ``returnPEFile`` sẽ trả về con trỏ trỏ đến các byte chứa file PE đó

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/a04b3175-e181-4c5f-ba02-d5662f35f661)

Mình sẽ viết một script bằng idapython để patch các byte trên ra dạng file PE để dùng cho sau này. File này tên là bin.exe

```python
len = 0x100000
addr = 0x00F7B020 # thay đổi tuỳ theo máy và lần debug
bin= idc.get_bytes(addr,int(len))
open(r"bin.exe","wb").write(bin)
```

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/63f954ff-965b-4351-a8ee-28901a24755e)

Quay trở lại hàm ``createPEFileandInjectItTocmdexe``, sau khi tạo tiến trình cmd.exe và tạo con trỏ đến các byte của file PE, hàm này thực hiện hàng loạt các bước xử lý phức tạp nhằm mục đích Inject các byte của file PE ở trên vào tiến trình cmd.exe được tạo ban đầu

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/f4551bf5-dddb-4739-bb90-5c32f574507f)

Quay lại hàm ``handle1``, hàm tiếp tục decrypt các string và resolve api, sau đó hàm thực hiện gọi ``CreateFileW`` với tham số truyền vào là ``\\.\pipe\KCSCCTF2022``. Việc sử dụng CreateFileW với tham số như trên nhằm tạo 1 kết nối dạng pipe với tiến trình khác, phần này sẽ được mình giải thích kĩ hơn ở dưới.

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/720ad6f4-8fb0-4979-88b6-dcbb6eca83f5)

### handle2 function

Hàm này sau khi decrypt các string và resolve api, nó thực hiện tạo hai key trên Registry của máy ở theo đường dẫn ``.KCSC\shell\open\command`` tại ``HKEY_CLASSES_ROOT``

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/a446e472-dbc8-43f1-a96d-4a0ada9d19bb)

Dưới đây là các key được tạo và giá trị của chúng sau khi thực hiện hàm trên

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/c5bfe5b8-ebb9-4096-8860-7768945d8a34)

### main

Quay về hàm main, sau khi nhập Flag, chương trình thực hiện hàm ``WriteFile`` với giá trị ``handleFile`` chính là handle của hàm ``CreateFileW`` được gọi ở hàm ``handle1``

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/bd77be4b-4db7-49f9-a8a5-64b7a9ce1632)

Nói qua về `Pipe`, trong hệ điều hành Windows, pipe (ống nối) được sử dụng để truyền dữ liệu giữa các tiến trình. Một pipe cho phép một tiến trình ghi dữ liệu vào nó và tiến trình khác đọc dữ liệu từ nó. Điều này cho phép truyền thông tin hoặc kết nối giữa các tiến trình độc lập.

Có hai loại pipe trong Windows: named pipe (ống có tên) và anonymous pipe (ống vô danh). Named pipe cho phép giao tiếp giữa các tiến trình không liên quan, trong khi anonymous pipe chỉ hoạt động trong cùng một tiến trình hoặc tiến trình con.

* **CreatePipe**: Tạo một anonymous pipe và trả về hai handle, một handle cho đọc và một handle cho ghi. API này được sử dụng để tạo một anonymous pipe giữa hai tiến trình.

* **CreateNamedPipe**: Tạo một named pipe và trả về một handle cho named pipe đã tạo. API này được sử dụng để tạo một named pipe cho giao tiếp giữa các tiến trình không liên quan.

* **ConnectNamedPipe**: Cho phép một tiến trình khác kết nối đến named pipe đã được tạo. API này được sử dụng sau khi tiến trình đã tạo named pipe sử dụng CreateNamedPipe.

* **ReadFile/WriteFile**: Đọc dữ liệu từ pipe hoặc ghi dữ liệu vào pipe. Hai API này được sử dụng để truyền dữ liệu qua pipe giữa các tiến trình.

Quay trở lại hàm ``main``, chương trình gọi ``ReadFile`` để hứng giá trị trả về từ tiến trình khác trong ống nối ``pipe``, và cuối cùng là in ra nó

Tổng kết lại, ta hiểu được cách hoạt động của chường trình như sau:
- Lấy resource trong file mixture.exe và decrypt thành 1 file PE
- Tạo tiến trình cmd.exe và inject file PE vừa decrypt vào tiến trình trên
- Dùng ``CreateFileW`` để thiết lập kết nối đến ``\\.\pipe\KCSCCTF2022``
- Yêu cầu người dùng nhập input, sau đó sử dụng ``WriteFile`` để truyền input trên qua tiến trình cmd.exe được tạo thông qua pipe
- cmd.exe sẽ xử lý input, cuối cùng chương tình gọi ``ReadFile`` để hứng lấy giá trị trả về, sau đó in chúng ra Console

Có thể thấy tiến trình cmd.exe đã bị inject file PE vào, vậy thì chắc chắn hàm xử lý input phải nằm ở trong file PE bị inject, tức là nằm trong file bin.exe được patch ra bên trên.

### Phân tích file bin.exe

Ở hàm main của file, sau khi decrypt các string và resolve api, có thể thấy chương trình đang thực hiện các hàm như ``CreateNamedPipeW``, ``ConnectNamedPipe`` để tạo kết nối đến ``\\.\pipe\KCSCCTF2022``. Sau đó gọi hàm ``ReadFile`` để hứng lấy input người dùng nhập vào từ tiến trình bên kia. Sau đó chường trình gọi hàm ``sub_74155A``

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/25c01745-3efd-434f-a859-5d589d48fad7)

Hàm ``sub_74155A`` hiểu đơn giản là đang tạo một thread mới cho chương trình và chạy đến thread được tạo, ở đây là chạy đến hàm ``encrypt_flag``

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/674653db-d55c-46ae-b8a0-5e167dd0ce57)

Tại hàm ``encrypt_flag``, sau khi decrypt các string và resolve api, chương trình sử dụng ``RegQueryValueExA`` để lấy các giá trị của các key trong Registry mà chúng ta đã tạo ở trên, sau đó thực hiện encrypt flag bằng các api trong ADVAPI32.DLL. Sau đó so sánh chúng với ``v18``

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/9e312b0a-33e2-480e-ba6f-a5cfb3e5d500)

Mình sẽ dựng lại một cách tương đối cách chương trình Encrypt Flag

```
cnRegKey = [0x05, 0x17, 0x2B, 0x0C, 0x22, 0x41, 0x0C, 0x2D, 0x0C, 0x22, 
  0x20, 0x5E, 0x1C, 0x22, 0xB8, 0x6F]
CryptAqquireContextA(phProv, 0, 0, 24, 0xF0000000)
&dword_195434{
  BLOBHEADER hdr{
    BYTE   bType = 0x8; // PLAINTEXTKEYBLOB
    BYTE   bVersion = 0x2; // CUR_BLOB_VERSION
    WORD   reserved = 0x0;
    ALG_ID aiKeyAlg = 0x6610; //CALG_AES_256
  }
  DWORD cbKeySize = 0x20
  BYTE rgbKeyData[32] = '1st't_7l@g_u_2h0uldn't_s5bm1t_1t'
}
CryptImportKey(hProv, &dword_195434, 44, 0, 0, phKey)
CryptSetKeyParam(hKey, 1, cnRegKey, 0)
CryptEncrypt(hKey, 0, 1, 0, input, &dwCount, 0x400)
unsigned char encFlag[] =
{
  0x99, 0x28, 0x67, 0x48, 0xB0, 0x56, 0xC3, 0x65, 0xA1, 0x6C, 
  0x11, 0x99, 0xFE, 0x88, 0x5A, 0xA4, 0x70, 0xFD, 0x5E, 0xA7, 
  0x96, 0x3A, 0x1F, 0xCC, 0xB2, 0xDF, 0xCB, 0x27, 0x8B, 0x7C, 
  0xC3, 0x96, 0xA8, 0x9E, 0x58, 0xBA, 0x9E, 0x97, 0x65, 0x13, 
  0x05, 0x24, 0x48, 0x6A, 0xBC, 0x7D, 0x19, 0x29
};
```

Cuối cùng chương trình quay về hàm ``main``, dựa vào giá trị trả về để tính chuối ``Flag is incorrect!`` hoặc ``Flag is correct!``, cuối cùng là truyền nó sang tiến trình bên kia.

### Decrypt Flag

Chương trình mã hoá input người dùng nhập vào bằng thuật toán AES-256, key và iv là hai giá trị của 2 key được tạo ở Registry bởi các hàm trước, dựa vào đó mình sẽ viết script để lấy flag

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
iv = bytes([0x05, 0x17, 0x2B, 0x0C, 0x22, 0x41, 0x0C, 0x2D, 0x0C, 0x22, 
  0x20, 0x5E, 0x1C, 0x22, 0xB8, 0x6F])
Key = b"1st't_7l@g_u_2h0uldn't_s5bm1t_1t"
ct = [
  0x99, 0x28, 0x67, 0x48, 0xB0, 0x56, 0xC3, 0x65, 0xA1, 0x6C, 
  0x11, 0x99, 0xFE, 0x88, 0x5A, 0xA4, 0x70, 0xFD, 0x5E, 0xA7, 
  0x96, 0x3A, 0x1F, 0xCC, 0xB2, 0xDF, 0xCB, 0x27, 0x8B, 0x7C, 
  0xC3, 0x96, 0xA8, 0x9E, 0x58, 0xBA, 0x9E, 0x97, 0x65, 0x13, 
  0x05, 0x24, 0x48, 0x6A, 0xBC, 0x7D, 0x19, 0x29
]
ct = bytes(ct)
enc =  AES.new(Key,AES.MODE_CBC,iv)
print(enc.decrypt(ct))
# KCSC{C0n9r@tul@t10n2_0n_mak1ng_1t(^.^)}
```

Script trên trả về ``b'KCSC{C0n9r@tul\xc6q10n2_0n_mak1ng_1t(^.^)}\x00\x08\x08\x08\x08\x08\x08\x08\x08'``, đến đây thì mình xin phép hô biến flag thành ``KCSC{C0n9r@tul@t10n2_0n_mak1ng_1t(^.^)}`` và submit thử :)))

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/c37ae23e-e272-4634-a234-ad5a951d535b)

# Flag

```KCSC{C0n9r@tul@t10n2_0n_mak1ng_1t(^.^)}```

# Note

Vẫn còn một vấn đề mình chưa giải quyết được, đó là liệu bài này có antidebug hay không

Khi mình nhập input là flag thật và không chạy debug, mình không hiểu tại sao kết quả nó lại như thế này :((

![image](https://github.com/noobmannn/KCSC_CTF_2024/assets/102444334/51eef860-c207-4d16-98bc-d679a2101ab8)

Mình sẽ cố gắng giải quyết vấn đề này trong tương lai gần nhất có thể, rất xin lỗi mọi người :(((

Script giải flag bằng C. Kết quả của script dưới là ``KCSC{C0n9r@tul╞q10n2_0n_mak1ng_1t(^.^)}``

```C
#include <windows.h>
#include <stdio.h>

void encFlag()
{
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        return;
    }
    BYTE key[32] = {0x31, 0x73, 0x74, 0x27, 0x74, 0x5F, 0x37, 0x6C, 0x40, 0x67,
                    0x5F, 0x75, 0x5F, 0x32, 0x68, 0x30, 0x75, 0x6C, 0x64, 0x6E,
                    0x27, 0x74, 0x5F, 0x73, 0x35, 0x62, 0x6D, 0x31, 0x74, 0x5F,
                    0x31, 0x74};
    typedef struct
    {
        BLOBHEADER hdr;
        DWORD cbKeySize;
        BYTE rgbKeyData[32];
    } KeyBLOB;
    KeyBLOB kb;
    kb.hdr.bType = PLAINTEXTKEYBLOB;
    kb.hdr.bVersion = CUR_BLOB_VERSION;
    kb.hdr.reserved = 0;
    kb.hdr.aiKeyAlg = CALG_AES_256;
    kb.cbKeySize = 0x20;
    CopyMemory(kb.rgbKeyData, key, 0x20);
    if (!CryptImportKey(hProv, (BYTE *)&kb, 0x2C, 0, 0, &hKey))
    {
        CryptReleaseContext(hProv, 0);
        return;
    }
    BYTE iv[] = {0x05, 0x17, 0x2B, 0x0C, 0x22, 0x41, 0x0C, 0x2D, 0x0C, 0x22,
                 0x20, 0x5E, 0x1C, 0x22, 0xB8, 0x6F};
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0))
    {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }
    BYTE enc[] = {0x99, 0x28, 0x67, 0x48, 0xB0, 0x56, 0xC3, 0x65, 0xA1, 0x6C,
                  0x11, 0x99, 0xFE, 0x88, 0x5A, 0xA4, 0x70, 0xFD, 0x5E, 0xA7,
                  0x96, 0x3A, 0x1F, 0xCC, 0xB2, 0xDF, 0xCB, 0x27, 0x8B, 0x7C,
                  0xC3, 0x96, 0xA8, 0x9E, 0x58, 0xBA, 0x9E, 0x97, 0x65, 0x13,
                  0x05, 0x24, 0x48, 0x6A, 0xBC, 0x7D, 0x19, 0x29};
    // BYTE enc[] = {0xf6, 0x99, 0x64, 0x46, 0x67, 0xfa, 0xe7, 0xf0, 0x82, 0x35, 0x3a, 0x6c, 0xa1, 0xbe, 0x56, 0xbb, 0x8b, 0x47, 0xb8, 0xe9, 0x50, 0xb6, 0xba, 0x69, 0x17, 0x2e, 0xb4, 0x15, 0x95, 0x51, 0xe2, 0x5f, 0xa, 0x22, 0x8e, 0x74, 0xd, 0xaf, 0x19, 0x5e, 0xd2, 0x6a, 0x4b, 0xea, 0x2c, 0xc2, 0xd2, 0x82};
    DWORD dwCount2 = 0x30;
    if (!CryptDecrypt(hKey, 0, 1, 0, enc, &dwCount2))
    {
        printf("error!!\n");
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }
    for (DWORD i = 0; i < dwCount2; ++i)
    {
        printf("%c", enc[i]);
    }
    printf("\n");
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
}

int main()
{
    encFlag();
    return 0;
}
```
