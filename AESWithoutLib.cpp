#include <iostream>
#include <fstream>
#include <string>
#include <locale>
#include <fcntl.h>
#include <codecvt>
#include <cstdlib>
#include <bitset>
#include <vector>
#include <thread>
#include <time.h>
#include <assert.h>

using namespace std;
typedef uint8_t byte;
typedef uint32_t word;

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
#define IOSYNTAX std::locale::global(std::locale(""))
#endif

// bảng sbox
const byte s_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};
// bảng inverted sbox
const byte inv_s_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};
//bảng rcon
const byte rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d};

//chuyển từ string sang wstring
wstring string_to_wstring(const string &utf8Str);
//chuyển wstring sang string
string wstring_to_string(const wstring &utf16Str);
// chuyển chuỗi ascii sang chuỗi hex
string text_to_hex(const string &textStr);
// PKCL7 padding
void PKCS7_padding(string &str);
// de PKCL7 padding
void de_PKCS7_padding(string &str);
// xor các phần từ của state với roundkey
void add_roundkey(byte *state, const byte *roundkey);
// thay thể với bảng s_box
void sub_bytes(byte *state);
// thay thể với bảng inv_s_box
void inv_sub_bytes(byte *state);
// shift row
void shift_row(byte *state);
// inv shift row
void inv_shift_row(byte *state);
// nhân hai phần tử của ma trận
byte FFmul(const byte &a, const byte &b);
// mix column
void mix_col(byte *state);
// inv mix column
void inv_mix_col(byte *state);
// key expand core
void KeyExpansionCore(byte *in, const int &i);
// key expansion
byte *KeyExpansion(const word *inputKey, const int &keysize);
// aes encrypt one block
void aes_encrypt(byte *en_msg, const byte *expandedKeys, const int &keysize);
// aes decrypt one block
void aes_decrypt(byte *de_msg, const byte *expandedKeys, const int &keysize);
// aes decrypt with CBC mode
void aes_encrypt_CBC_mode(const string &plain, string &cipher, const byte *expandedKeys, const int &keysize, const byte iv[16]);
// aes decrypt thread core 
void aes_decrypt_CBC_core(byte *recovered, const byte *cipher, const byte *expandedKeys, const int &keysize, const byte *iv, const int &nBlock);
// aes decrypt with CBC mode
void aes_decrypt_CBC_mode(const string &cipher, string &recovered, const byte *expandedKeys, const int &keysize, const byte iv[16]);
// loại bỏ các ký tự '\n'trong stdin
void DiscardLFFromStdin(const int &num);
// nhập string from screen
void InputPlainFromScreen(string &plain);
// nhập chuỗi từ file
void InputStringFromFile(const string &filename, string &str, const int &strlen);
// giai đoạn nhập
void InputProcess(string &plain, string &key, int &keysize, string &iv);
// giai đoạn xuất
void OutputProcess(const string &plain, const string &key, const string &iv);

int main()
{
    // đồng bộ với wcin, wcout
    IOSYNTAX;
    // khai báo các biến cần thiết
    clock_t start, end;
    string plain, key, iv;
    string cipher, recovered;
    int keysize;
    // giai đoạn nhập
    InputProcess(plain, key, keysize, iv);
    // giai đoạn xuất
    //OutputProcess(plain, key, iv);
    start = clock();
    for (int i = 0; i < 1000; ++i)
    {
        // tạo expansion key
        byte *enExpandedkeys = KeyExpansion((word *)key.c_str(), keysize);
        // encrypt
        cipher.clear();
        aes_encrypt_CBC_mode(plain, cipher, enExpandedkeys, keysize, (byte *)iv.c_str());
        delete[] enExpandedkeys;
    }
    end = clock();
    wcout << "Cipher text: " << string_to_wstring(text_to_hex(cipher)) << endl;
    // in thời gian thực hiện encrypt 1000 lần
    wcout << "Time for encryption (1 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;

    try
    {
        start = clock();
        for (int i = 0; i < 1000; ++i)
        {
            // tạo expansion key
            byte *deExpandedkeys = KeyExpansion((word *)key.c_str(), keysize);
            // decrypt
            recovered.clear();
            aes_decrypt_CBC_mode(cipher, recovered, deExpandedkeys, keysize, (byte *)iv.c_str());
            delete[] deExpandedkeys;
        }
        end = clock();
        // in kết quả recoverd
        wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
    }

    // in thời gian decrypt 1000 lần
    wcout << "Time for decryption (1 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
    return 0;
}

wstring string_to_wstring(const string &utf8Str)
{
    wstring_convert<codecvt_utf8_utf16<wchar_t>> conv;
    return conv.from_bytes(utf8Str);
}

string wstring_to_string(const wstring &utf16Str)
{
    wstring_convert<codecvt_utf8_utf16<wchar_t>> conv;
    return conv.to_bytes(utf16Str);
}

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

void PKCS7_padding(string &str)
{
    // n bằng 16 trừ đi độ dài của crStr module 16 (16 - crStr mod 16)
    // thêm vào crStr n bytes với giá trị mỗi byte bằng n;
    int numByteEtra = 16 - str.length() % 16;
    int n = str.length() + numByteEtra;
    str.resize(n, numByteEtra);
}

void de_PKCS7_padding(string &str)
{
    // n bằng giá trị của phần tử cuối cùng của crStr (n=crStr[crStr.lengh()-1])
    // cắt n bytes từ bên phải của crStr;
    int byteExtra = str[str.length() - 1];
    str.resize(str.length() - byteExtra);
}

void add_roundkey(byte *state, const byte *roundkey)
{
    word *a = (word *)state;
    word *b = (word *)roundkey;
    a[0] ^= b[0];
    a[1] ^= b[1];
    a[2] ^= b[2];
    a[3] ^= b[3];
}

void sub_bytes(byte *state)
{
    int i = 16;
    while (i--)
        state[i] = s_box[state[i]];
}

void inv_sub_bytes(byte *state)
{
    int i = 16;
    while (i--)
        state[i] = inv_s_box[state[i]];
}

void shift_row(byte *state)
{
    //shift trái cột bằng cách thay thế theo bảng
    //  0   4   8   12
    //  5   9   13   1
    //  10  14  2   6
    //  15  15  7   11

    //hàng 2(dịch trái 1 bytes)
    byte tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    //hàng 3(dịch trái 2 bytes)
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    //hàng 4(dịch trái 3 bytes)
    tmp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = tmp;
}

void inv_shift_row(byte *state)
{

    //shift phải cột bằng cách thay thế theo bảng
    //  0   1   5   12
    //  13  14  2   9
    //  10  11  15  6
    //  7   8   12  3

    //hàng 2(dịch phải 1 bytes)
    byte tmp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp;

    //hàng 3(dịch phải 2 bytes)
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    //hàng 4(dịch phải 3 bytes)
    tmp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = tmp;
}

void mix_col(byte *state)
{
    byte tmp[4];
    int j;
    for (int i = 0; i < 4; ++i)
    {
        j = i << 2;
        tmp[0] = state[j];
        tmp[1] = state[j + 1];
        tmp[2] = state[j + 2];
        tmp[3] = state[j + 3];
        state[j] = FFmul(0x02, tmp[0]) ^ FFmul(0x03, tmp[1]) ^ FFmul(0x01, tmp[2]) ^ FFmul(0x01, tmp[3]);
        state[j + 1] = FFmul(0x02, tmp[1]) ^ FFmul(0x03, tmp[2]) ^ FFmul(0x01, tmp[3]) ^ FFmul(0x01, tmp[0]);
        state[j + 2] = FFmul(0x02, tmp[2]) ^ FFmul(0x03, tmp[3]) ^ FFmul(0x01, tmp[0]) ^ FFmul(0x01, tmp[1]);
        state[j + 3] = FFmul(0x02, tmp[3]) ^ FFmul(0x03, tmp[0]) ^ FFmul(0x01, tmp[1]) ^ FFmul(0x01, tmp[2]);
    }
}

byte FFmul(const byte &a, const byte &b)
{
    byte bw[4];
    byte res = 0;
    int i;
    bw[0] = b;
    for (i = 1; i < 4; i++)
    {
        bw[i] = bw[i - 1] << 1;
        if (bw[i - 1] & 0x80)
        {
            bw[i] ^= 0x1b;
        }
    }
    for (i = 0; i < 4; i++)
    {
        if ((a >> i) & 0x01)
        {
            res ^= bw[i];
        }
    }
    return res;
}

void inv_mix_col(byte *state)
{
    byte tmp[4];
    int j;
    for (int i = 0; i < 4; ++i)
    {
        j = i << 2;
        tmp[0] = state[j];
        tmp[1] = state[j + 1];
        tmp[2] = state[j + 2];
        tmp[3] = state[j + 3];
        state[j] = FFmul(0x0e, tmp[0]) ^ FFmul(0x0b, tmp[1]) ^ FFmul(0x0d, tmp[2]) ^ FFmul(0x09, tmp[3]);
        state[j + 1] = FFmul(0x0e, tmp[1]) ^ FFmul(0x0b, tmp[2]) ^ FFmul(0x0d, tmp[3]) ^ FFmul(0x09, tmp[0]);
        state[j + 2] = FFmul(0x0e, tmp[2]) ^ FFmul(0x0b, tmp[3]) ^ FFmul(0x0d, tmp[0]) ^ FFmul(0x09, tmp[1]);
        state[j + 3] = FFmul(0x0e, tmp[3]) ^ FFmul(0x0b, tmp[0]) ^ FFmul(0x0d, tmp[1]) ^ FFmul(0x09, tmp[2]);
    }
}


void KeyExpansionCore(byte in[4], const int &i)
{
    // dịch trái 1 bytes
    byte t = in[0];
    in[0] = in[1];
    in[1] = in[2];
    in[2] = in[3];
    in[3] = t;

    // thay thế với sbox
    in[0] = s_box[in[0]];
    in[1] = s_box[in[1]];
    in[2] = s_box[in[2]];
    in[3] = s_box[in[3]];

    // xor in[0] với bảng rcon
    in[0] ^= rcon[i];
}

byte *KeyExpansion(const word *inputKey, const int &keysize)
{
    int expandedkeyLength;
    switch (keysize)
    {
    case 16:
        expandedkeyLength = 44;
        break;
    case 24:
        expandedkeyLength = 52;
    default:
        expandedkeyLength = 60;
        break;
    }
    word *expandedKeys = new word[expandedkeyLength];
    // đưa keysize được tính theo bytes thành wkeysize đươc tính theo word
    int wkeysize = keysize >> 2;
    // gán vào expandedkey trước 16 bytes key gốc
    int i = wkeysize;
    while (i--)
        expandedKeys[i] = inputKey[i];

    int wordGenerated = wkeysize; // số word32 hiện có của expandkey
    int rconIteration = 1;        // vị trí rcon
    word *tmpCore = new word;

    while (wordGenerated < expandedkeyLength)
    {
        // lấy 4 bytes cuối hiện có của expandedkey gán vào tmpCore
        *tmpCore = *(expandedKeys + wordGenerated - 1);
        // thực hiện expansion với tmp và rconIteration++
        if (wordGenerated % wkeysize == 0)
            KeyExpansionCore((byte *)tmpCore, rconIteration++);
        // xor expandedKeys[bytesGenerated] với tmpCore;
        *(expandedKeys + wordGenerated) = *(expandedKeys + wordGenerated - wkeysize) ^ *tmpCore;
        // tăng wordGenerated
        ++wordGenerated;
    }
    return (byte *)expandedKeys;
}

void aes_encrypt(byte *en_msg, const byte *expandedKeys, const int &keysize)
{
    // số round
    int numberOfRounds = 6 + (keysize >> 2);

    // xor en_msg với 16 bytes expandedkey đầu tiên
    add_roundkey(en_msg, expandedKeys);

    // thực hiện tiếp 9 round đầu
    for (int i = 1; i < numberOfRounds; ++i)
    {
        // thay thế với s_box
        sub_bytes(en_msg);
        // shift trái
        shift_row(en_msg);
        // nhân cột với ma trận
        mix_col(en_msg);
        // xor en_msg với key round
        add_roundkey(en_msg, expandedKeys + (i << 4));
    }

    //round cuối
    // shift trái
    sub_bytes(en_msg);
    // nhân cột với ma trận
    shift_row(en_msg);
    // xor en_msg với key round
    add_roundkey(en_msg, expandedKeys + (numberOfRounds << 4));
}

void aes_decrypt(byte *de_msg, const byte *expandedKeys, const int &keysize)
{
    // số round
    int numberOfRounds = 6 + (keysize >> 2);

    //vòng đầu
    //xor en_msg với key round cuối
    add_roundkey(de_msg, expandedKeys + (numberOfRounds << 4));
    //shift phải
    inv_shift_row(de_msg);
    // thay thế với inv_s_box
    inv_sub_bytes(de_msg);
    // 9 round tiếp theo
    for (int i = numberOfRounds - 1; i > 0; i--)
    {
        //xor en_msg với key round
        add_roundkey(de_msg, expandedKeys + (i << 4));
        // nhân cột với ma trận đảo
        inv_mix_col(de_msg);
        //shift phải
        inv_shift_row(de_msg);
        // thay thế với inv_s_box
        inv_sub_bytes(de_msg);
    }
    //xor de_msg với round key đầu
    add_roundkey(de_msg, expandedKeys);
}

void aes_encrypt_CBC_mode(const string &plain, string &cipher, const byte *expandedKeys, const int &keysize, const byte *iv)
{
    // chuyển plain text ban đầu vào cipher text
    cipher = plain;
    // padding cipher text
    PKCS7_padding(cipher);
    // số block
    int n = cipher.length() >> 4;

    // khai báo các con trỏ word để lưu địa chỉ cipher và iv
    word *wcipher = (word *)&cipher[0];
    word *wiv = (word *)iv;

    // xor 16 bytes đầu cipher với 16 bytes iv
    wcipher[0] ^= wiv[0];
    wcipher[1] ^= wiv[1];
    wcipher[2] ^= wiv[2];
    wcipher[3] ^= wiv[3];
    // encrypt block thứ nhất
    aes_encrypt((byte *)&cipher[0], expandedKeys, keysize);

    // encrypt n-1 block còn lại
    int j;
    for (int i = 1; i < n; ++i)
    {
        // xor block cipher[i] với block cipher[i-1]
        j = (i << 2);
        wcipher[j] ^= wcipher[j - 4];
        wcipher[j + 1] ^= wcipher[j - 3];
        wcipher[j + 2] ^= wcipher[j - 2];
        wcipher[j + 3] ^= wcipher[j - 1];
        aes_encrypt((byte *)&cipher[i << 4], expandedKeys, keysize);
    }
}

void aes_decrypt_CBC_core(byte *recovered, const byte *cipher, const byte *expandedKeys, const int &keysize, const byte *iv, const int &nBlock)
{

    // khai báo các con trỏ word để lưu địa chỉ recovered,cipher và iv
    word *wrecovered = (word *)&recovered[0];
    word *wcipher = (word *)&cipher[0];
    word *wiv = (word *)iv;

    // decrypt block đầu tiên và xor với iv
    aes_decrypt((byte *)&recovered[0], expandedKeys, keysize);

    wrecovered[0] ^= wiv[0];
    wrecovered[1] ^= wiv[1];
    wrecovered[2] ^= wiv[2];
    wrecovered[3] ^= wiv[3];
    // decrypt n-1 block tiếp theo
    int j;
    for (int i = 1; i < nBlock; ++i)
    {
        // decrypt block i
        aes_decrypt((byte *)&recovered[i << 4], expandedKeys, keysize);
        // xor recoveredBlock[i] với cipherBlock[i-1]
        j = i << 2;
        wrecovered[j] ^= wcipher[j - 4];
        wrecovered[j + 1] ^= wcipher[j - 3];
        wrecovered[j + 2] ^= wcipher[j - 2];
        wrecovered[j + 3] ^= wcipher[j - 1];
    }
}

void aes_decrypt_CBC_mode(const string &cipher, string &recovered, const byte *expandedKeys, const int &keysize, const byte *iv)
{
       // chuyển cipher text ban đầu vào recovered text
    recovered = cipher;
    // biến tạm
    int j;
    // tổng số block
    int n = cipher.length() >> 4;
    // số thread
    int nThread = n >> 8;
    thread *decrypt_threads = new thread[nThread + 1];
    // kiểm tra nếu số block < 256 thì k khởi tạo thread
    if (nThread)
    {
        // khởi tạo thread 0
        decrypt_threads[0] = thread(aes_decrypt_CBC_core, (byte *)&recovered[0], (byte *)&cipher[0], expandedKeys, keysize, iv, 256);
        for (int i = 1; i < nThread; ++i)
        {
            // vị trí của recovered text được chuyền vào thread(i*256)
            j = i << 12;
            // khởi tạo thread
            decrypt_threads[i] = thread(aes_decrypt_CBC_core, (byte *)&recovered[j], (byte *)&cipher[j], expandedKeys, keysize, (byte *)&cipher[j - 16], 256);
        }
        // kiểm tra xem có thread thiếu hay k(block<256)
        if (n % 256)
        {
            // vị trí của recovered text của thread cuối (thread k đủ 256 block)
            j = nThread << 12;
            decrypt_threads[nThread] = thread(aes_decrypt_CBC_core, (byte *)&recovered[j], (byte *)&cipher[j], expandedKeys, keysize, (byte *)&cipher[j - 16], n % 256);
            ++nThread;
        }
        //phần lỗi
        for (int i = 0; i < nThread; ++i)
        {
            //assert(decrypt_threads[i].joinable() == true);
            if (decrypt_threads[i].joinable())
                decrypt_threads[i].join();
        }
    }
    else
        aes_decrypt_CBC_core((byte *)&recovered[0], (byte *)&cipher[0], expandedKeys, keysize, iv, n);
    // de padding
    de_PKCS7_padding(recovered);
    //giải phóng thread
    delete[] decrypt_threads;
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

void InputKeyFromSreen(string &key, const int &keysize)
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
    key = wstring_to_string(wkey);
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

void InputStringFromFile(const string &filename, string &str, const int &strlen)
{
    fstream readFile(filename, ios::in);
    readFile.seekg(0, fstream::end);
    int fileLength = readFile.tellg();
    readFile.seekg(0, fstream::beg);
    //wcout<<fileLength<<endl;
    if (fileLength < strlen)
    {
        wcout << "file is not long enough";
        return;
    }
    if (readFile.is_open())
    {
        char *buffer = new char[strlen + 1];
        readFile.read(buffer, strlen);
        str = string(buffer, strlen);
        delete[] buffer;
    }
    else
    {
        wcout << "Unable to open file";
        exit(-1);
    }
    readFile.close();
}

void InputProcess(string &plain, string &key, int &keysize, string &iv)
{

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
        InputStringFromFile("test18000bytes.txt", plain, 18000);
        break;
    case 2:
        InputPlainFromScreen(plain);
        break;
    default:
        wcout << "What did you choose?\n";
        exit(-1);
    }

    // chọn giá trị keysize
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

    // chọn cách lấy key
    wcout << "1. From File AES_key.key\n";
    wcout << "2. From console (" << keysize << " bytes)\n";
    wcout << "Select your key: ";
    wcin >> choice;
    switch (choice)
    {
    case 1:
        InputStringFromFile("AES_key.key", key, keysize);
        break;
    case 2:
        InputKeyFromSreen(key, keysize);
        break;
    default:
        wcout << "What did you choose?\n";
        exit(-1);
    }

    // chọn cách lấy initial vector
    wcout << "1. From File AES_iv.key\n";
    wcout << "2. From console (16 bytes)\n";
    wcout << "Select your initial vector: ";
    wcin >> choice;
    switch (choice)
    {
    case 1:
        InputStringFromFile("AES_iv.key", iv, 16);
        break;
    case 2:
        InputKeyFromSreen(iv, 16);
        break;
    default:
        wcout << "What did you choose?\n";
        exit(-1);
    }

    // hoàn thành nhập input
    wcout << "Input process succeeded\n";
    wcout << "---------------------\n";
}

void OutputProcess(const string &plain, const string &key, const string &iv)
{
    wcout << "plain text size: " << plain.length() << endl;
    wcout << "plain text: " << string_to_wstring(plain) << endl;
    wcout << "key size: " << key.size() << endl;
    wcout << "key: " << string_to_wstring(text_to_hex(key)) << endl;
    wcout << "vi size: " << iv.size() << endl;
    wcout << "vi: " << string_to_wstring(text_to_hex(iv)) << endl;
    wcout << endl;
}
