#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::wcin;
using std::wcout;

#include <fstream>
using std::fstream;
using std::ios;

#include <string>
using std::getline;
using std::string;
using std::to_string;
using std::wstring;

#include <locale>
using std::wstring_convert;

#include <fcntl.h>
#include <codecvt>
using std::codecvt_utf8_utf16;

#include <cstdlib>
using std::exit;

#include <time.h>

#include <assert.h>

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include "cryptopp/cryptlib.h"
using CryptoPP::byte;
using CryptoPP::Exception;

#include <cryptopp/files.h>
using CryptoPP::FileSink;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::FileSource;
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_CTS_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
//CBC,ECB,OFB, CFB, CBC-CTS, CTR

#ifdef _WIN32
// thư viện dùng dể setmode trong window
#include <io.h>
// số ký tự "\n" cần bỏ trong stdin sau wcin trong window
#define DISCARD 2
// đồng bộ hóa cho wcin và wcout trong window
void ioSyntax()
{
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
}
#define IOSYNTAX ioSyntax()
#else
// số ký tự "\n" cần bỏ trong stdin sau wcin trong linux
#define DISCARD 1
// đồng bộ wcin và wcout cho linux
#define IOSYNTAX std::locale::global(std::locale(""))
#endif

void DiscardLFFromStdin(const int &);
// chuyển string về wstring
wstring string_to_wstring(const string &);
// chuyển wstring về string
string wstring_to_string(const wstring &);
// nhập plain text từ màn hình và lưu vào biến plain(string)
void InputPlainFromScreen(string &);
// nhập plain text từ file
void InputPlainFromFile(string &plain);
// nhập key và ghi vào file vào file DES_key.key
void InputKeyFromSreen(SecByteBlock &);
// chọn key ngẫu nhiên và lưu vào file DES_key.key
void RandomKey(SecByteBlock &);
// nhập key from file
void InputKeyFromFile(SecByteBlock &, const string &);
// nhập initial vector và ghi vào file vào file DES_iv.key
void InputIVFromSreen(SecByteBlock &);
// chọn initial vector ngẫu nhiên và lưu vào file DES_iv.key
void RandomIV(SecByteBlock &);
// chuyển sexbyteblock trong thư viện crypto++ thành string hex
string SecByteBlockToStrHex(const SecByteBlock &key);
// DES với ecb mode
void DES_ECBMode(const string &, const SecByteBlock &);
// DES với cbc mode
void DES_CBCMode(const string &, const SecByteBlock &, const SecByteBlock &);
// DES với cbc_cts mode
void DES_CBC_CTSMode(const string &, const SecByteBlock &, const SecByteBlock &);
// DES với CFB mode
void DES_CFBMode(const string &, const SecByteBlock &, const SecByteBlock &);
// DES với OFB mode
void DES_OFBMode(const string &, const SecByteBlock &, const SecByteBlock &);
// DES với CTR mode
void DES_CTRMode(const string &, const SecByteBlock &, const SecByteBlock &);
// giai đoạn lựu chọn và nhập các input
void InputProcess(SecByteBlock &, const int &, SecByteBlock &);
// in ra input
void OutputProcess(const string &, const SecByteBlock &, const SecByteBlock &);
// giai đoạn chọn mode
void ModeProcess(const string &);

int main()
{
    // đồng bộ IO theo OS
    IOSYNTAX;
    // khái báo biến plain để lưu trữ plain text
    string plain;
    // main process
    wcout << "Welcome to DES cryptography\n";
    wcout << "---------------------\n\n";
    wcout << "1. From file test18000bytes.txt\n";
    wcout << "2. From console\n";
    wcout << "Select your plaintext: ";

    // chọn cách lấy plaintext
    int choice;
    wcin >> choice;
    switch (choice)
    {
    case 1:
        InputPlainFromFile(plain);
        break;
    case 2:
        InputPlainFromScreen(plain);
        break;
    default:
        wcout << "What did you choose?\n";
        exit(-1);
    }

    ModeProcess(plain);
    return 0;
}

void DiscardLFFromStdin(const int &num)
{
    int tmp = num;
    int c;
    while (tmp--)
        while ((c = getwchar()) != '\n')
            if (c == WEOF)
                return;
}

wstring string_to_wstring(const string &utf8Str)
{
    //chuyển từ UTF8 sang UTF16
    wstring_convert<codecvt_utf8_utf16<wchar_t>> conv;
    return conv.from_bytes(utf8Str);
}

string wstring_to_string(const wstring &utf16Str)
{
    //chuyển từ UTF16 sang UTF8
    wstring_convert<codecvt_utf8_utf16<wchar_t>> conv;
    return conv.to_bytes(utf16Str);
}

void RandomKey(SecByteBlock &key)
{
    // khai báo đối tượng prng thuộc class CryptoPP::AutoSeededRandomPool
    // để khởi tạo key block (key)
    AutoSeededRandomPool prng;

    //khởi tạo ngẫu nghiên key block với kích thước bằng keysize đã chọn
    key.resize(8);
    // random key
    prng.GenerateBlock(key, key.size());
}

void RandomIV(SecByteBlock &iv)
{
    // khai báo đối tượng prng thuộc class CryptoPP::AutoSeededRandomPool
    // để khởi tạo Initialization vector (iv)
    AutoSeededRandomPool prng;

    //khởi tạo ngẫu nghiên iv block với bằng keysize đã chọn
    iv.resize(8);
    //random iv
    prng.GenerateBlock(iv, iv.size());
}

void InputKeyFromSreen(SecByteBlock &key)
{
    //nhập key từ bàn phím
    wstring wkey;
    int tmp = 0;
    do
    {
        // nhập và kiểm tra key, nếu sai nhập lại
        if (tmp)
            wcout << "wrong input!Please input again: ";
        else
            wcout << "Please input key (8 bytes): ";

        //fflush(stdin);
        DiscardLFFromStdin(DISCARD - tmp);
        getline(wcin, wkey);
        tmp = 1;
    } while (wkey.length() != 8);

    // chuyển wkey(wstring) về key(string)
    string skey = wstring_to_string(wkey);

    StringSource ss(skey, false);

    key.resize(8);
    CryptoPP::ArraySink copykey(key, key.size());
    ss.Detach(new Redirector(copykey));
    ss.Pump(key.size());
}

void InputKeyFromFile(SecByteBlock &key, const string &filename)
{
    key.resize(8);
    FileSource fs(&filename[0], false);
    CryptoPP::ArraySink copykey(key, key.size());
    fs.Detach(new Redirector(copykey));
    fs.Pump(key.size());
}

void InputIVFromSreen(SecByteBlock &iv)
{
    //nhập iv từ bàn phím
    wstring wiv;
    int tmp = 0;
    do
    {
        // nhập và kiểm tra iv, nếu sai nhập lại
        if (tmp)
            wcout << "wrong input!Please input again: ";
        else
            wcout << "Please input initial vector (8 bytes): ";

        DiscardLFFromStdin(DISCARD - tmp);
        getline(wcin, wiv);
        tmp = 1;
    } while (wiv.length() != 8);

    // chuyển wvi(wstring) về svi(string)
    string siv = wstring_to_string(wiv);

    StringSource ss(siv, false);

    iv.resize(8);
    CryptoPP::ArraySink copyiv(iv, iv.size());

    ss.Detach(new Redirector(copyiv));
    ss.Pump(iv.size());
}

void InputPlainFromScreen(string &plain)
{
    //nhập plaintext từ bàn phím
    wstring wplain;

    // nhập và kiểm tra plaintext
    wcout << "Please input plaintext: ";

    DiscardLFFromStdin(DISCARD);
    getline(wcin, wplain);
    // chuyển wplain(wstring) về plain(string)
    plain = wstring_to_string(wplain);
}

void InputPlainFromFile(string &plain)
{
    fstream readFile("test18000bytes.txt", ios::in);
    if (readFile.is_open())
        getline(readFile, plain);
    else
    {
        wcout << "Unable to open file";
        exit(-1);
    }
    readFile.close();
}

void InputProcess(SecByteBlock &key, const int &hiv, SecByteBlock &iv)
{
    int choice;
    // chọn cách lấy key
    wcout << "1. Random\n";
    wcout << "2. From console (8 bytes)\n";
    wcout << "3. From File DES_key.key\n";
    wcout << "Select your key: ";
    wcin >> choice;
    switch (choice)
    {
    case 1:
        RandomKey(key);
        break;
    case 2:
        InputKeyFromSreen(key);
        break;
    case 3:
        InputKeyFromFile(key, "DES_key.key");
        break;
    default:
        wcout << "What did you choose?\n";
        exit(-1);
    }

    // chọn cách lấy initial vector
    if (hiv)
    {
        wcout << "1. Random\n";
        wcout << "2. From console (8 bytes)\n";
        wcout << "3. From File DES_iv.key\n";
        wcout << "Select your initial vector: ";
        wcin >> choice;
        switch (choice)
        {
        case 1:
            RandomIV(iv);
            break;
        case 2:
            InputIVFromSreen(iv);
            break;
        case 3:
            InputKeyFromFile(iv, "DES_iv.key");
            break;
        default:
            wcout << "What did you choose?\n";
            exit(-1);
        }
    }

    // hoàn thành nhập input
    wcout << "Input process succeeded\n";
    wcout << "---------------------\n";
}

string SecByteBlockToStrHex(const SecByteBlock &key)
{
    string hex;
    StringSource(key, key.size(), true,
                 new HexEncoder(
                     new StringSink(hex)));
    return hex;
}

void OutputProcess(const string &plain, const SecByteBlock &key, const int &hiv, const SecByteBlock &iv)
{
    wcout << "plain text size: " << plain.length() << endl;
    wcout << "plain text: " << string_to_wstring(plain) << endl;
    wcout << "key size: " << key.size() << endl;
    wcout << "key: " << string_to_wstring(SecByteBlockToStrHex(key)) << endl;
    if (hiv)
    {
        wcout << "vi size: " << iv.size() << endl;
        wcout << "vi: " << string_to_wstring(SecByteBlockToStrHex(iv)) << endl;
    }
    wcout << endl;
}

void ModeProcess(const string &plain)
{
    SecByteBlock key;
    SecByteBlock iv;
    string authText;
    int choice;
    while (true)
    {
        wcout << "1. ECB mode\n";
        wcout << "2. CBC mode\n";
        wcout << "3. CFB mode\n";
        wcout << "4. OFB mode\n";
        wcout << "5. CTR mode\n";
        wcout << "6. exit\n";
        wcout << "Select your mode: ";
        wcin >> choice;
        switch (choice)
        {
        case 1:
            InputProcess(key, 0, iv);
            OutputProcess(plain, key, 0, iv);
            DES_ECBMode(plain, key);
            break;
        case 2:
            InputProcess(key, 1, iv);
            OutputProcess(plain, key, 1, iv);
            DES_CBCMode(plain, key, iv);
            break;
        case 3:
            InputProcess(key, 1, iv);
            OutputProcess(plain, key, 1, iv);
            DES_CFBMode(plain, key, iv);
            break;
        case 4:
            InputProcess(key, 1, iv);
            OutputProcess(plain, key, 1, iv);
            DES_OFBMode(plain, key, iv);
            break;
        case 5:
            InputProcess(key, 1, iv);
            OutputProcess(plain, key, 1, iv);
            DES_CTRMode(plain, key, iv);
            break;
        case 6:
            wcout << "Bye\n";
            exit(0);
        default:
            wcout << "What have you choice?\n";
            exit(-1);
        }
        wcout << "Selected mode succeeded\n";
        wcout << "---------------------\n";
    }
}

void DES_ECBMode(const string &plain, const SecByteBlock &key)
{
    // sử dụng 2 biến cipher về recovered để lưu kết quả encrypt và decrypt
    string cipher, recovered;
    // biến tạm dùng để lưu kết quả tạm thời
    string encoded;
    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        // DES Encryption với ECB mode
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            ECB_Mode<DES>::Encryption e;
            // set key
            e.SetKey(key, key.size());

            cipher.clear();
            //padding(mặc định là PKCS7_PADDING) và encrypt (kết quả encrypt được lưu vào chuỗi cipher)
            /*  PKCS5_PADDING:
				Thêm byte đệm vào block cuối cùng nếu như block đó không đủ 16 byte mỗi byte thêm vào bằng với tổng số byte thiếu
				nếu block đó đủ 16 bytes thì thêm vào 1 block nữa có giá trị từng phần từ bằng 10(hex)
			*/
            StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        end = clock(); //kết thúc tính giờ

        //Đưa chuỗi cipher về dạng chuỗi có thể đọc được (HEX string)
        encoded.clear();
        StringSource(cipher, true,
                     new HexEncoder(
                         new StringSink(encoded), true, 16, " "));
        // in kết quả cipher ở dạng chuỗi hex
        wcout << "Cipher text: " << string_to_wstring(encoded) << endl;
        // in thời gian thực hiện encrypt 10000 lần
        wcout << "Time for encryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    try
    {
        // DES Decryption với ECB mode
        start = clock(); // bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            ECB_Mode<DES>::Decryption d;
            // set key
            d.SetKey(key, key.size());

            recovered.clear();
            // thực hiện giải mã sau đó xóa các byte đệm đã thêm vào trước đó
            StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        end = clock(); // kết thúc tính giờ
        // in kết quả recoverd
        wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
        // in thời gian decrypt 10000 lần
        wcout << "Time for decryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void DES_CBCMode(const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
{
    // sử dụng 2 biến cipher về recovered để lưu kết quả encrypt và decrypt
    string cipher, recovered;
    // biến tạm dùng để lưu kết quả tạm thời
    string encoded;
    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        // DES Encryption với CBC mode
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            CBC_Mode<DES>::Encryption e;
            // set key
            e.SetKeyWithIV(key, key.size(), iv, iv.size());

            cipher.clear();
            //padding(mặc định là PKCS7_PADDING) và encrypt (kết quả encrypt được lưu vào chuỗi cipher)
            /*  PKCS5_PADDING:
				Thêm byte đệm vào block cuối cùng nếu như block đó không đủ 16 byte mỗi byte thêm vào bằng với tổng số byte thiếu
				nếu block đó đủ 16 bytes thì thêm vào 1 block nữa có giá trị từng phần từ bằng 10(hex)
			*/
            StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        end = clock(); // kết thúc tính giờ

        //Đưa chuỗi cipher về dạng chuỗi có thể đọc được (HEX string)
        encoded.clear();
        StringSource(cipher, true,
                     new HexEncoder(
                         new StringSink(encoded), true, 16, " "));
        // in kết quả cipher ở dạng chuỗi hex
        wcout << "Cipher text: " << string_to_wstring(encoded) << endl;
        // in thời gian thực hiện encrypt 10000 lần
        wcout << "Time for encryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    try
    {
        // DES Decryption với CBC mode
        start = clock(); // bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            CBC_Mode<DES>::Decryption d;
            // set key
            d.SetKeyWithIV(key, key.size(), iv, iv.size());

            recovered.clear();
            // thực hiện giải mã sau đó xóa các byte đệm đã thêm vào trước đó
            StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        end = clock(); //kết thúc tính giờ
        // in kết quả recoverd
        wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
        // in thời gian decrypt 10000 lần
        wcout << "Time for decryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void DES_CFBMode(const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
{

    // sử dụng 2 biến cipher về recovered để lưu kết quả encrypt và decrypt
    string cipher, recovered;
    // biến tạm dùng để lưu kết quả tạm thời
    string encoded;
    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        // DES Encryption với CFB mode
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            CFB_Mode<DES>::Encryption e;
            // set key
            e.SetKeyWithIV(key, key.size(), iv, iv.size());

            cipher.clear();
            //encrypt (kết quả encrypt được lưu vào chuỗi cipher)
            StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        end = clock(); //kết thúc tính giờ

        //Đưa chuỗi cipher về dạng chuỗi có thể đọc được (HEX string)
        encoded.clear();
        StringSource(cipher, true,
                     new HexEncoder(
                         new StringSink(encoded), true, 16, " "));
        // in kết quả cipher ở dạng chuỗi hex
        wcout << "Cipher text: " << string_to_wstring(encoded) << endl;
        // in thời gian thực hiện encrypt 10000 lần
        wcout << "Time for encryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    try
    {
        // DES Decryption với CFB mode
        start = clock(); // bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            CFB_Mode<DES>::Decryption d;
            // set key
            d.SetKeyWithIV(key, key.size(), iv, iv.size());

            recovered.clear();
            // thực hiện giải mã sau đó
            StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        end = clock(); //kết thúc tính giờ
        // in kết quả recoverd
        wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
        // in thời gian decrypt 10000 lần
        wcout << "Time for decryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void DES_OFBMode(const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
{

    // sử dụng 2 biến cipher về recovered để lưu kết quả encrypt và decrypt
    string cipher, recovered;
    // biến tạm dùng để lưu kết quả tạm thời
    string encoded;
    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        // DES Encryption với OFB mode
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            OFB_Mode<DES>::Encryption e;
            // set key
            e.SetKeyWithIV(key, key.size(), iv, iv.size());

            cipher.clear();
            //encrypt (kết quả encrypt được lưu vào chuỗi cipher)
            StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        end = clock(); //kết thúc tính giờ

        //Đưa chuỗi cipher về dạng chuỗi có thể đọc được (HEX string)
        encoded.clear();
        StringSource(cipher, true,
                     new HexEncoder(
                         new StringSink(encoded), true, 16, " "));
        // in kết quả cipher ở dạng chuỗi hex
        wcout << "Cipher text: " << string_to_wstring(encoded) << endl;
        // in thời gian thực hiện encrypt 10000 lần
        wcout << "Time for encryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    try
    {
        // DES Decryption với OFB mode
        start = clock(); // bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            OFB_Mode<DES>::Decryption d;
            // set key
            d.SetKeyWithIV(key, key.size(), iv, iv.size());

            recovered.clear();
            // thực hiện giải mã sau đó
            StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        end = clock(); //kết thúc tính giờ
        // in kết quả recoverd
        wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
        // in thời gian decrypt 10000 lần
        wcout << "Time for decryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void DES_CTRMode(const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
{
    // sử dụng 2 biến cipher về recovered để lưu kết quả encrypt và decrypt
    string cipher, recovered;
    // biến tạm dùng để lưu kết quả tạm thời
    string encoded;
    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        // DES Encryption với CTR mode
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            CTR_Mode<DES>::Encryption e;
            // set key
            e.SetKeyWithIV(key, key.size(), iv, iv.size());

            cipher.clear();
            //encrypt (kết quả encrypt được lưu vào chuỗi cipher)
            StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        end = clock(); //kết thúc tính giờ

        //Đưa chuỗi cipher về dạng chuỗi có thể đọc được (HEX string)
        encoded.clear();
        StringSource(cipher, true,
                     new HexEncoder(
                         new StringSink(encoded), true, 16, " "));
        // in kết quả cipher ở dạng chuỗi hex
        wcout << "Cipher text: " << string_to_wstring(encoded) << endl;
        // in thời gian thực hiện encrypt 10000 lần
        wcout << "Time for encryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    try
    {
        // DES Decryption với CTR mode
        start = clock(); // bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            CTR_Mode<DES>::Decryption d;
            // set key
            d.SetKeyWithIV(key, key.size(), iv, iv.size());

            recovered.clear();
            // thực hiện giải mã sau đó
            StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        end = clock(); //kết thúc tính giờ
        // in kết quả recoverd
        wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
        // in thời gian decrypt 10000 lần
        wcout << "Time for decryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}