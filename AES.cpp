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

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_CTS_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
//CBC,ECB,OFB, CFB, CBC-CTS, CTR
#include "cryptopp/xts.h"
using CryptoPP::XTS;
// XTS
#include "cryptopp/ccm.h"
using CryptoPP::CCM;
// CCM
#include "cryptopp/gcm.h"
using CryptoPP::GCM;
// GCM

#ifdef _WIN32
// thư viện dùng dể setmode trong window
#include <io.h>
// số ký tự "\n" cần bỏ trong stdin sau wcin trong window 
#define DISCARD 2
// đồng bộ hóa cho wcin và wcout trong window
void io_syntax()
{
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
}
#define IOSYNTAX io_syntax()
#else
// số ký tự "\n" cần bỏ trong stdin sau wcin trong linux
#define DISCARD 1
// đồng bộ wcin và wcout cho linux
#define IOSYNTAX std::locale::global (std::locale (""))
#endif


void DiscardLFFromStdin(const int&);
// chuyển string về wstring
wstring string_to_wstring(const string &);
// chuyển wstring về string
string wstring_to_string(const wstring &);
// nhập plain text từ màn hình và lưu vào biến plain(string)
void InputPlainFromScreen(string &);
// nhập plain text từ file
void InputPlainFromFile(string &plain);
// nhập key và ghi vào file vào file AES_key.key
void InputKeyFromSreen(SecByteBlock &, const int &);
// chọn key ngẫu nhiên và lưu vào file AES_key.key
void RandomKey(SecByteBlock &, const int &);
// nhập key from file
void InputKeyFromFile(SecByteBlock &, const int &, const string &);
// nhập initial vector và ghi vào file vào file AES_iv.key
void InputIVFromSreen(SecByteBlock &, const int &);
// chọn initial vector ngẫu nhiên và lưu vào file AES_iv.key
void RandomIV(SecByteBlock &, const int &);
// nhập authentication text
void InputAuthTextFromScreen(string &);
// chuyển sexbyteblock trong thư viện crypto++ thành string hex
string SecByteBlockToStrHex(const SecByteBlock &key);
// AES với ecb mode
void AES_ECBMode(const string &, const SecByteBlock &);
// AES với cbc mode
void AES_CBCMode(const string &, const SecByteBlock &, const SecByteBlock &);
// AES với cbc_cts mode
void AES_CBC_CTSMode(const string &, const SecByteBlock &, const SecByteBlock &);
// AES với CFB mode
void AES_CFBMode(const string &, const SecByteBlock &, const SecByteBlock &);
// AES với OFB mode
void AES_OFBMode(const string &, const SecByteBlock &, const SecByteBlock &);
//AES với CTR mode
void AES_CTRMode(const string &, const SecByteBlock &, const SecByteBlock &);
//AES với XTS mode
void AES_XTSMode(const string &, const SecByteBlock &, const SecByteBlock &);
// AES với CCM mode
void AES_CCMMode(const string &, const SecByteBlock &, const SecByteBlock &, const string &);
//AES với GCM mode
void AES_GCMMode(const string &, const SecByteBlock &, const SecByteBlock &, const string &);
// giai đoạn lựu chọn và nhập các input
void InputProcess(SecByteBlock &, int &, const int &, SecByteBlock &, const int &, const int &h, string &);
// in ra input
void OutputProcess(const string &, const SecByteBlock &, const int &, const SecByteBlock &, const int &, string &);
// giai đoạn chọn mode
void ModeProcess(const string &);
string text_to_hex(const string &textStr)
{
    string hexStr;
    hexStr.resize(textStr.size() * 2);
    const size_t a = 'A' - 1;

    for (size_t i = 0, c = textStr[0] & 0xFF; i < hexStr.size(); c = textStr[i / 2] & 0xFF)
    {
        hexStr[i++] = c > 0x9F ? (c / 16 - 9) | a : c / 16 | '0';
        hexStr[i++] = (c & 0xF) > 9 ? (c % 16 - 9) | a : c % 16 | '0';
    }
    return hexStr;
}

int main()
{
    // đồng bộ IO theo OS
    IOSYNTAX;
    // khái báo biến plain để lưu trữ plain text
    string plain;
    // main process
    wcout << "Welcome to AES cryptography\n";
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

void DiscardLFFromStdin(const int& num)
{
    int tmp = num;
    int c;
    while(tmp--)
        while((c=getwchar())!='\n') if(c==WEOF) return;
    
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

void RandomKey(SecByteBlock &key, const int &keysize)
{
    // khai báo đối tượng prng thuộc class CryptoPP::AutoSeededRandomPool
    // để khởi tạo key block (key)
    AutoSeededRandomPool prng;

    //khởi tạo ngẫu nghiên key block với kích thước bằng keysize đã chọn
    key.resize(keysize);
    // random key
    prng.GenerateBlock(key, key.size());
}

void RandomIV(SecByteBlock &iv, const int &visize)
{
    // khai báo đối tượng prng thuộc class CryptoPP::AutoSeededRandomPool
    // để khởi tạo Initialization vector (iv)
    AutoSeededRandomPool prng;

    //khởi tạo ngẫu nghiên iv block với bằng keysize đã chọn
    iv.resize(visize);
    //random iv
    prng.GenerateBlock(iv, iv.size());
}

void InputKeyFromSreen(SecByteBlock &key, const int &keysize)
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
            wcout << "Please input key (" << keysize << " bytes): ";

        //fflush(stdin);
        DiscardLFFromStdin(DISCARD - tmp);
        getline(wcin, wkey);
        tmp = 1;
    } while (int(wkey.length()) != keysize);

    // chuyển wkey(wstring) về key(string)
    string skey = wstring_to_string(wkey);

    StringSource ss(skey, false);

    key.resize(keysize);
    CryptoPP::ArraySink copykey(key, keysize);
    ss.Detach(new Redirector(copykey));
    ss.Pump(keysize);
}

void InputKeyFromFile(SecByteBlock &key, const int &keysize, const string &filename)
{
    key.resize(keysize);
    FileSource fs(&filename[0], false);
    CryptoPP::ArraySink copykey(key, key.size());
    fs.Detach(new Redirector(copykey));
    fs.Pump(key.size());
}

void InputIVFromSreen(SecByteBlock &iv, const int &ivsize)
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
            wcout << "Please input initial vector (" << ivsize << " bytes): ";

        DiscardLFFromStdin(DISCARD - tmp);
        getline(wcin, wiv);
        tmp = 1;
    } while (int(wiv.length()) != ivsize);

    // chuyển wvi(wstring) về svi(string)
    string siv = wstring_to_string(wiv);

    StringSource ss(siv, false);

    iv.resize(ivsize);
    CryptoPP::ArraySink copyiv(iv, ivsize);

    ss.Detach(new Redirector(copyiv));
    ss.Pump(ivsize);
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

void InputAuthTextFromScreen(string &authText)
{
    //nhập plaintext từ bàn phím
    wstring wauthText;
    // nhập authenticaiton text
    wcout << "Please input authentication text: ";

    DiscardLFFromStdin(DISCARD);
    getline(wcin, wauthText);
    // chuyển wauthText(wstring) về authText(string)
    authText = wstring_to_string(wauthText);
}

void InputProcess(SecByteBlock &key, int &keysize, const int &hiv, SecByteBlock &iv, const int &ivsize, const int &hauth, string &authText)
{
    // nhập authText
    if (hauth)
        InputAuthTextFromScreen(authText);

    int choice;
    // chọn giá trị keysize
    if (!keysize)
    {
        wcout << "1. 16 bytes (128 bits)\n";
        wcout << "2. 24 bytes (192 bits)\n";
        wcout << "3. 32 bytes (256 bits)\n";
        wcout << "Select your keysize: ";
        wcin >> choice;
        switch (choice)
        {
        case 1:
            keysize = 16;
            break;
        case 2:
            keysize = 24;
            break;
        case 3:
            keysize = 32;
            break;
        default:
            wcout << "What did you choose?\n";
            exit(-1);
        }
    }

    // chọn cách lấy key
    wcout << "1. Random\n";
    wcout << "2. From console (" << keysize << " bytes)\n";
    wcout << "3. From File AES_key.key\n";
    wcout << "Select your key: ";
    wcin >> choice;
    switch (choice)
    {
    case 1:
        RandomKey(key, keysize);
        break;
    case 2:
        InputKeyFromSreen(key, keysize);
        break;
    case 3:
        InputKeyFromFile(key, keysize, "AES_key.key");
        break;
    default:
        wcout << "What did you choose?\n";
        exit(-1);
    }

    // chọn cách lấy initial vector
    if (hiv)
    {
        wcout << "1. Random\n";
        wcout << "2. From console (" << ivsize << " bytes)\n";
        wcout << "3. From File AES_iv.key\n";
        wcout << "Select your initial vector: ";
        wcin >> choice;
        switch (choice)
        {
        case 1:
            RandomIV(iv, ivsize);
            break;
        case 2:
            InputIVFromSreen(iv, ivsize);
            break;
        case 3:
            InputKeyFromFile(iv, ivsize, "AES_iv.key");
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

void OutputProcess(const string &plain, const SecByteBlock &key, const int &hiv, const SecByteBlock &iv, const int &hauth, string &authText)
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
    if (hauth)
    {
        wcout << "authentication text size: " << authText.length() << endl;
        wcout << "authentication text: " << string_to_wstring(authText) << endl;
    }
    wcout << endl;
}

void ModeProcess(const string &plain)
{
    int keysize;
    SecByteBlock key;
    SecByteBlock iv;
    string authText;
    int choice;
    while (true)
    {
        keysize = 0;
        wcout << "1. ECB mode\n";
        wcout << "2. CBC mode\n";
        wcout << "3. CFB mode\n";
        wcout << "4. OFB mode\n";
        wcout << "5. CTR mode\n";
        wcout << "6. XTS mode\n";
        wcout << "7. CCM mode\n";
        wcout << "8. GCM mode\n";
        wcout << "9. exit\n";
        wcout << "Select your mode: ";
        wcin >> choice;
        switch (choice)
        {
        case 1:
            InputProcess(key, keysize, 0, iv, 16, 0, authText);
            OutputProcess(plain, key, 0, iv, 0, authText);
            AES_ECBMode(plain, key);
            break;
        case 2:
            InputProcess(key, keysize, 1, iv, 16, 0, authText);
            OutputProcess(plain, key, 1, iv, 0, authText);
            AES_CBCMode(plain, key, iv);
            break;
        case 3:
            InputProcess(key, keysize, 1, iv, 16, 0, authText);
            OutputProcess(plain, key, 1, iv, 0, authText);
            AES_CFBMode(plain, key, iv);
            break;
        case 4:
            InputProcess(key, keysize, 1, iv, 16, 0, authText);
            OutputProcess(plain, key, 1, iv, 0, authText);
            AES_OFBMode(plain, key, iv);
            break;
        case 5:
            InputProcess(key, keysize, 1, iv, 16, 0, authText);
            OutputProcess(plain, key, 1, iv, 0, authText);
            AES_CTRMode(plain, key, iv);
            break;
        case 6:
            keysize = 32;
            InputProcess(key, keysize, 1, iv, 16, 0, authText);
            OutputProcess(plain, key, 1, iv, 0, authText);
            AES_XTSMode(plain, key, iv);
            break;
        case 7:
            InputProcess(key, keysize, 1, iv, 12, 1, authText);
            OutputProcess(plain, key, 1, iv, 1, authText);
            AES_CCMMode(plain, key, iv, authText);
            break;
        case 8:
            InputProcess(key, keysize, 1, iv, 12, 1, authText);
            OutputProcess(plain, key, 1, iv, 1, authText);
            AES_GCMMode(plain, key, iv, authText);
            break;
        case 9:
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

void AES_ECBMode(const string &plain, const SecByteBlock &key)
{
    // sử dụng 2 biến cipher về recovered để lưu kết quả encrypt và decrypt
    string cipher, recovered;
    // biến tạm dùng để lưu kết quả tạm thời
    string encoded;
    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        // AES Encryption với ECB mode
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            ECB_Mode<AES>::Encryption e;
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
        // AES Decryption với ECB mode
        start = clock(); // bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            ECB_Mode<AES>::Decryption d;
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

void AES_CBCMode(const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
{
    // sử dụng 2 biến cipher về recovered để lưu kết quả encrypt và decrypt
    string cipher, recovered;
    // biến tạm dùng để lưu kết quả tạm thời
    string encoded;
    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        // AES Encryption với CBC mode
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            CBC_Mode<AES>::Encryption e;
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
        // // in kết quả cipher ở dạng chuỗi hex
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
        // AES Decryption với CBC mode
        start = clock(); // bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            CBC_Mode<AES>::Decryption d;
            // set key
            d.SetKeyWithIV(key, key.size(), iv, iv.size());

            recovered.clear();
            // thực hiện giải mã sau đó xóa các byte đệm đã thêm vào trước đó
            StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        end = clock(); //kết thúc tính giờ
        // in kết quả recoverd
        wcout << "Recovered text: " << string_to_wstring(encoded) << endl;
        // in thời gian decrypt 10000 lần
        wcout << "Time for decryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void AES_CFBMode(const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
{

    // sử dụng 2 biến cipher về recovered để lưu kết quả encrypt và decrypt
    string cipher, recovered;
    // biến tạm dùng để lưu kết quả tạm thời
    string encoded;
    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        // AES Encryption với CFB mode
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            CFB_Mode<AES>::Encryption e;
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
        // AES Decryption với CFB mode
        start = clock(); // bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            CFB_Mode<AES>::Decryption d;
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

void AES_OFBMode(const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
{

    // sử dụng 2 biến cipher về recovered để lưu kết quả encrypt và decrypt
    string cipher, recovered;
    // biến tạm dùng để lưu kết quả tạm thời
    string encoded;
    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        // AES Encryption với OFB mode
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            OFB_Mode<AES>::Encryption e;
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
        // AES Decryption với OFB mode
        start = clock(); // bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            OFB_Mode<AES>::Decryption d;
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

void AES_CTRMode(const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
{
    // sử dụng 2 biến cipher về recovered để lưu kết quả encrypt và decrypt
    string cipher, recovered;
    // biến tạm dùng để lưu kết quả tạm thời
    string encoded;
    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        // AES Encryption với CTR mode
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            CTR_Mode<AES>::Encryption e;
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
        // AES Decryption với CTR mode
        start = clock(); // bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            CTR_Mode<AES>::Decryption d;
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

void AES_XTSMode(const string &plain, const SecByteBlock &key, const SecByteBlock &iv)
{
    // sử dụng 2 biến cipher về recovered để lưu kết quả encrypt và decrypt
    string cipher, recovered;
    // biến tạm dùng để lưu kết quả tạm thời
    string encoded;
    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        // AES Encryption với XTS mode
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            XTS<AES>::Encryption e;
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
        // AES Decryption với XTS mode
        start = clock(); // bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            XTS<AES>::Decryption d;
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

void AES_CCMMode(const string &plain, const SecByteBlock &key, const SecByteBlock &iv, const string &authText)
{
    const int TAG_SIZE = 16;

    // lưu encrypt plaintext và authText vào cipher
    string cipher, encoded;

    // Recovered cipher text
    string rauthText, rplain;

    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            // AES Encryption với GCM mode
            CCM<AES>::Encryption e;
            // set key
            e.SetKeyWithIV(key, key.size(), iv, iv.size());
            e.SpecifyDataLengths(authText.size(), plain.size(), 0);
            // encrypt filter
            cipher.clear();
            AuthenticatedEncryptionFilter ef(e,
                                             new StringSink(cipher), false, TAG_SIZE);

            // gửi thông điệp xác thực ở dạng clear text theo kênh AAD
            ef.ChannelPut("AAD", (const byte *)authText.data(), authText.size());
            ef.ChannelMessageEnd("AAD");

            // cần gửi thông điệp xác thực trước khi gửi cipher text
            // gửi cipher text (encrypt data và mac) theo kênh default("")
            ef.ChannelPut("", (const byte *)plain.data(), plain.size());
            ef.ChannelMessageEnd("");
        }
        end = clock(); //kết thúc tính giờ

        // chuyển cipher về dạng đọc được (hex)
        encoded.clear();
        StringSource(cipher, true,
                     new HexEncoder(new StringSink(encoded), true, 16, " "));
        // in kết quả cipher ở dạng chuỗi hex
        wcout << "Cipher text: " << string_to_wstring(encoded) << endl;
        // in thời gian thực hiện encrypt 10000 lần
        wcout << "Time for encryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        cerr << endl;
    }

    try
    {
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            // gán trực tiếp rauthText =authText do authText được gửi ở dạng clear text
            rauthText = authText;
            // chia cipher thành 2 phần enc(en_plain) và mac(tag)
            string enc = cipher.substr(0, cipher.length() - TAG_SIZE);
            string mac = cipher.substr(cipher.length() - TAG_SIZE);

            CCM<AES>::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv, iv.size());
            d.SpecifyDataLengths(rauthText.size(), enc.size(), 0);

            assert(cipher.size() == enc.size() + mac.size());
            assert(TAG_SIZE == mac.size());

            // đưa ra exception nếu kiểm tra hoặc giải mã thất bại
            AuthenticatedDecryptionFilter df(d, NULL,
                                             AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                                 AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                             TAG_SIZE);

            df.ChannelPut("", (const byte *)mac.data(), mac.size());
            df.ChannelPut("AAD", (const byte *)authText.data(), authText.size());
            df.ChannelPut("", (const byte *)enc.data(), enc.size());
            df.ChannelMessageEnd("AAD");
            df.ChannelMessageEnd("");

            // kiểm tra sự toàn vẹn của dữ liệu lần cuối
            assert(df.GetLastResult());

            // lấy data from các kênh
            string retrieved;
            size_t n = -1;

            // Plain text recovered from enc.data()
            df.SetRetrievalChannel("");
            n = (size_t)df.MaxRetrievable();
            retrieved.resize(n);

            if (n > 0)
                df.Get((byte *)retrieved.data(), n);
            rplain = retrieved;
        }
        end = clock(); //kết thúc tính giờ

        // in ra kết quả decrypt
        wcout << "recovered plain text:" << string_to_wstring(rplain) << endl;
        wcout << "recovered plain text length: " << rplain.size() << endl;
        wcout << "recovered authentication text: " << string_to_wstring(rauthText) << endl;
        wcout << "recovered authentication text length: " << rauthText.size() << endl;
        // in thời gian decrypt 10000 lần
        wcout << "Time for decryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        cerr << endl;
    }
}

void AES_GCMMode(const string &plain, const SecByteBlock &key, const SecByteBlock &iv, const string &authText)
{
    const int TAG_SIZE = 16;

    // lưu encrypt plaintext và authText vào cipher
    string cipher, encoded;

    // Recovered cipher text
    string rauthText, rplain;

    //sử dụng clock để tính thời gian encrypt và decrypt
    clock_t start, end;

    try
    {
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            // AES Encryption với GCM mode
            GCM<AES>::Encryption e;
            // set key
            e.SetKeyWithIV(key, key.size(), iv, iv.size());

            // encrypt filter
            cipher.clear();
            AuthenticatedEncryptionFilter ef(e,
                                             new StringSink(cipher), false, TAG_SIZE);

            // gửi thông điệp xác thực ở dạng clear text theo kênh AAD
            ef.ChannelPut("AAD", (const byte *)authText.data(), authText.size());
            ef.ChannelMessageEnd("AAD");

            // cần gửi thông điệp xác thực trước khi gửi cipher text
            // gửi cipher text (encrypt data và mac) theo kênh default("")
            ef.ChannelPut("", (const byte *)plain.data(), plain.size());
            ef.ChannelMessageEnd("");
        }
        end = clock(); //kết thúc tính giờ

        // chuyển cipher về dạng đọc được (hex)
        encoded.clear();
        StringSource(cipher, true,
                     new HexEncoder(new StringSink(encoded), true, 16, " "));
        // in kết quả cipher ở dạng chuỗi hex
        wcout << "Cipher text: " << string_to_wstring(encoded) << endl;
        // in thời gian thực hiện encrypt 10000 lần
        wcout << "Time for encryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        cerr << endl;
    }

    try
    {
        start = clock(); //bắt đầu tính giờ
        for (int i = 0; i < 10000; i++)
        {
            // chia cipher thành 2 phần enc(en_plain) và mac(tag)
            string enc = cipher.substr(0, cipher.length() - TAG_SIZE);
            string mac = cipher.substr(cipher.length() - TAG_SIZE);

            assert(cipher.size() == enc.size() + mac.size());
            assert(TAG_SIZE == mac.size());

            // gán trực tiếp rauthText =authText do authText được gửi ở dạng clear text
            rauthText = authText;

            GCM<AES>::Decryption d;
            d.SetKeyWithIV(key, key.size(), iv, iv.size());

            // đưa ra exception nếu kiểm tra hoặc giải mã thất bại
            AuthenticatedDecryptionFilter df(d, NULL,
                                             AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                                 AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                             TAG_SIZE);

            df.ChannelPut("", (const byte *)mac.data(), mac.size());
            df.ChannelPut("AAD", (const byte *)authText.data(), authText.size());
            df.ChannelPut("", (const byte *)enc.data(), enc.size());
            df.ChannelMessageEnd("AAD");
            df.ChannelMessageEnd("");

            // kiểm tra sự toàn vẹn của dữ liệu lần cuối
            assert(df.GetLastResult());

            // lấy data from các kênh
            string retrieved;
            size_t n = -1;

            // Plain text recovered from enc.data()
            df.SetRetrievalChannel("");
            n = (size_t)df.MaxRetrievable();
            retrieved.resize(n);

            if (n > 0)
                df.Get((byte *)retrieved.data(), n);
            rplain = retrieved;
        }
        end = clock(); //kết thúc tính giờ

        // in ra kết quả decrypt
        wcout << "recovered plain text:" << string_to_wstring(rplain) << endl;
        wcout << "recovered plain text length: " << rplain.size() << endl;
        wcout << "recovered authentication text: " << string_to_wstring(rauthText) << endl;
        wcout << "recovered authentication text length: " << rauthText.size() << endl;
        // in thời gian decrypt 10000 lần
        wcout << "Time for decryption (10 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        cerr << endl;
    }
}