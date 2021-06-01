#include <iostream>
#include <string>
#include <bitset>
#include <locale>
#include <fcntl.h>
#include <codecvt>
#include <cstdlib>
#include <fstream>
#include <time.h>
#include <thread>
using namespace std;

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

// bản hóa vị đầu
int initial_perm[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7};
//số lần shift phải key theo round
int shift_table[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
// bảng giảm key xuống 48
int key_comp[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32};
// P-box
int exp_d[48] = {
    32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1};
// S-box
int s[8][4][16] = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};
// bảng hoán vị theo round
int per[32] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25};
// bảng loại bỏ 8 bit key đầu
int keyp[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4};
// bảng hoán vị cuối
int final_perm[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25};
// string to wstring
wstring string_to_wstring(const string &utf8Str)
{
    wstring_convert<codecvt_utf8_utf16<wchar_t>> conv;
    return conv.from_bytes(utf8Str);
}
// wstring to string
string wstring_to_string(const wstring &utf16Str)
{
    wstring_convert<codecvt_utf8_utf16<wchar_t>> conv;
    return conv.to_bytes(utf16Str);
}
// PKCS cho block 64 bit
void PKCS5_padding(string &str)
{
    // n bằng 8 trừ đi độ dài của crStr module 8 (8 - crStr mod 8)
    // thêm vào crStr n bytes với giá trị mỗi byte bằng n;
    int numByteEtra = 8 - str.length() % 8;
    int n = str.length() + numByteEtra;
    str.resize(n, numByteEtra);
}
// de PKCS cho block 64 bit
void de_PKCS5_padding(string &str)
{
    // n bằng giá trị của phần tử cuối cùng của crStr (n=crStr[crStr.lengh()-1])
    // cắt n bytes từ bên phải của crStr;
    int byteExtra = str[str.length() - 1];
    str.resize(str.length() - byteExtra);
}
// string 16 byte to bitset<64>
void str_to_word64(const uint8_t *str_c, bitset<64> &block)
{
    // chuyển chuỗi str[4] về 1 word(64 bit)
    block.reset();
    bitset<64> offset(0xFF);
    for (int i = 0; i < 7; i++)
    {
        block |= (((bitset<64>)str_c[i]) & offset);
        block <<= 8;
    }
    block |= (((bitset<64>)str_c[7]) & offset);
}
// string bitset<64> 16 byte
void word64_to_str(const bitset<64> &block, uint8_t *str_c)
{
    // chuyển một word(64 bit) về chuỗi str[4]
    unsigned long long tmp;
    for (int i = 0; i < 8; i++)
    {
        tmp = 0;
        tmp += (block[8 * i]);
        tmp += (block[8 * i + 1] << 1);
        tmp += (block[8 * i + 2] << 2);
        tmp += (block[8 * i + 3] << 3);
        tmp += (block[8 * i + 4] << 4);
        tmp += (block[8 * i + 5] << 5);
        tmp += (block[8 * i + 6] << 6);
        tmp += (block[8 * i + 7] << 7);
        str_c[7 - i] = char(tmp);
    }
}
// chuỗi ascii thành chuỗi hex
string text_to_hex(const string &textStr)
{
    // chuyển chuỗi ascii về chuỗi hex
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
// lấy 56 bits key
bitset<56> get_fifty_six_bit_key(const bitset<64> &binKey)
{
    // lấy 58 key theo bảng keyp
    bitset<56> fs_key;
    for (int i = 0; i < 56; i++)
    {
        fs_key[55 - i] = binKey[64 - keyp[i]];
    }
    return fs_key;
}
// shift left
void shift_left(bitset<28> &binkey, int n)
{
    // shift trái n bit
    //bitset<28> key_shifted = binkey;
    bitset<1> tmp;
    while (n--)
    {
        tmp[0] = binkey[27];
        binkey <<= 1;
        binkey[0] = tmp[0];
    }
}
// shift right
void shift_right(bitset<28> &binkey, int n)
{
    // shift phải n bit
    //bitset<28> key_shifted = binkey;
    bitset<1> tmp;
    while (n--)
    {
        tmp[0] = binkey[0];
        binkey >>= 1;
        binkey[27] = tmp[0];
    }
}
// lấy 48 bit ky từ 56 bit key
bitset<48> get_forty_eight_bit_key(const bitset<56> &binKey)
{
    // lấy 48 bitkey theo bảng key_comp
    bitset<48> fe_key;
    for (int i = 0; i < 48; i++)
        fe_key[47 - i] = binKey[56 - key_comp[i]];
    return fe_key;
}
// hoán vị đầu
bitset<64> inital_permute(const bitset<64> &binPlain)
{
    //hoán vị các phần từ bằng bảng initial_pern
    bitset<64> ip_plain;
    for (int i = 0; i < 64; i++)
    {
        ip_plain[63 - i] = binPlain[64 - initial_perm[i]];
    }
    return ip_plain;
}
// mở rộng ky từ 32 lên 48
bitset<48> expand_to_forty_eight_bit(const bitset<32> &binPlain)
{
    //mở rộng plain từ 32 bit thành 64 bit
    bitset<48> fe_expand;
    for (int i = 0; i < 48; i++)
        fe_expand[47 - i] = binPlain[32 - exp_d[i]];
    return fe_expand;
}
// thay thế với sbox
bitset<32> Sbox_substitute(const bitset<48> &binXor1)
{
    // thay thế các phần tử với bản sbox
    bitset<32> sbox;
    for (int i = 0; i < 8; i++)
    {
        int row = 2 * binXor1[47 - i * 6] + binXor1[42 - i * 6];
        int col = 8 * binXor1[46 - i * 6] + 4 * binXor1[45 - i * 6] + 2 * binXor1[44 - i * 6] + binXor1[43 - i * 6];
        int val = s[i][row][col];
        bitset<4> temp(val);
        sbox[4 * (7 - i)] = temp[0];
        sbox[4 * (7 - i) + 1] = temp[1];
        sbox[4 * (7 - i) + 2] = temp[2];
        sbox[4 * (7 - i) + 3] = temp[3];
    }
    return sbox;
}
// thay thế pbox
bitset<32> Pbox_permute(const bitset<32> &binSbox)
{
    // hoán vị các phần từ theo bảng per
    bitset<32> Pbox;
    for (int i = 0; i < 32; i++)
        Pbox[31 - i] = binSbox[32 - per[i]];
    return Pbox;
}
// hoán vị lần cuối
bitset<64> final_permute(const bitset<64> &text)
{
    //hoán vị các phần từ theo bảng final_pern
    bitset<64> fn_per;
    for (int i = 0; i < 64; i++)
    {
        fn_per[63 - i] = text[64 - final_perm[i]];
    }
    return fn_per;
}
// tạo key round
bitset<48> *gernerate_key(const bitset<64> &binKey)
{
    bitset<48> *roundkey = new bitset<48>[16];
    bitset<56> fs_binKey = get_fifty_six_bit_key(binKey);

    // chia key làm hai khối phải, trái
    bitset<28> binKey_left(bitset<28>((fs_binKey >> 28).to_ullong()));
    bitset<28> binKey_right(bitset<28>(((fs_binKey << 28) >> 28).to_ullong()));
    bitset<56> fs_roundkey;
    for (int i = 0; i < 16; ++i)
    {
        //shift key
        shift_left(binKey_left, shift_table[i]);
        shift_left(binKey_right, shift_table[i]);
        fs_roundkey = bitset<56>(binKey_left.to_ullong());
        fs_roundkey <<= 28;
        fs_roundkey |= bitset<56>(binKey_right.to_ullong());
        //giảm khích thước của roundkey xuống 48
        roundkey[i] = get_forty_eight_bit_key(fs_roundkey);
    }
    return roundkey;
}
// encrypt 1 block
void des_encrypt(const bitset<64> &plain, bitset<64> &cipher, const bitset<48> *roundkey)
{
    // hóa vị đầu
    bitset<64> binPlain = inital_permute(plain);

    // chia plain test làm 2 khối phải, trái
    bitset<32> binPlain_left(bitset<32>((binPlain >> 32).to_ullong()));
    bitset<32> binPlain_right(bitset<32>(((binPlain << 32) >> 32).to_ullong()));

    for (int i = 0; i < 15; i++)
    {

        // mở rộng plain text bên phải lên 48 bit
        bitset<48> bin_right_expanded = expand_to_forty_eight_bit(binPlain_right);

        // XOR Roundkey và plain text bên phải sau khi đã mở rộng
        bitset<48> xor1 = roundkey[i] ^ bin_right_expanded;

        // subtitution Sbox
        bitset<32> Sbox = Sbox_substitute(xor1);

        // hoán vị Pbox
        bitset<32> Pbox = Pbox_permute(Sbox);

        // XOR Pbox và binPlain_left
        binPlain_left = Pbox ^ binPlain_left;

        // đổi trái, phải
        swap(binPlain_left, binPlain_right);
    }

    // mở rộng plain text bên phải lên 48 bit
    bitset<48> bin_right_expanded = expand_to_forty_eight_bit(binPlain_right);

    // XOR Roundkey và plain text bên phải sau khi đã mở rộng
    bitset<48> xor1 = roundkey[15] ^ bin_right_expanded;

    // subtitution Sbox
    bitset<32> Sbox = Sbox_substitute(xor1);

    // hoán vị Pbox
    bitset<32> Pbox = Pbox_permute(Sbox);

    // XOR Pbox và binPlain_left
    binPlain_left = Pbox ^ binPlain_left;

    // hoán vị lần cuối
    bitset<64> binCombine;
    binCombine |= bitset<64>(binPlain_left.to_ullong());
    binCombine <<= 32;
    binCombine |= bitset<64>(binPlain_right.to_ullong());
    cipher = final_permute(binCombine);
}
// decrypt 1 block
void des_decrypt(const bitset<64> &cipher, bitset<64> &recovered, const bitset<48> *roundkey)
{
    bitset<64> bincipher = cipher;

    // hóa vị đầu
    bincipher = inital_permute(bincipher);

    // chia cipher test làm 2 khối phải, trái
    bitset<32> binCipher_left(bitset<32>((bincipher >> 32).to_ullong()));
    bitset<32> binCipher_right(bitset<32>(((bincipher << 32) >> 32).to_ullong()));

    for (int i = 15; i > 0; --i)
    {
        // mở rộng cipher text bên phải lên 48 bit
        bitset<48> bin_right_expanded = expand_to_forty_eight_bit(binCipher_right);

        // XOR fe_binRoundkey và cipher text bên phải sau khi đã mở rộng
        bitset<48> xor1 = roundkey[i] ^ bin_right_expanded;

        // subtitution Sbox
        bitset<32> Sbox = Sbox_substitute(xor1);

        // hoán vị Pbox
        bitset<32> Pbox = Pbox_permute(Sbox);

        // XOR Pbox và binCipher_left
        binCipher_left = Pbox ^ binCipher_left;

        // đổi trái, phải
        swap(binCipher_left, binCipher_right);
    }

    // mở rộng cipher text bên phải lên 48 bit
    bitset<48> bin_right_expanded = expand_to_forty_eight_bit(binCipher_right);

    // XOR fe_binRoundkey và cipher text bên phải sau khi đã mở rộng
    bitset<48> xor1 = roundkey[0] ^ bin_right_expanded;

    // subtitution Sbox
    bitset<32> Sbox = Sbox_substitute(xor1);

    // hoán vị Pbox
    bitset<32> Pbox = Pbox_permute(Sbox);

    // XOR Pbox và binCipher_left
    binCipher_left = Pbox ^ binCipher_left;

    // hoán vị lần cuối
    bitset<64> binCombine;
    binCombine |= bitset<64>(binCipher_left.to_ullong());
    binCombine <<= 32;
    binCombine |= bitset<64>(binCipher_right.to_ullong());
    recovered = final_permute(binCombine);
}
// encrypt with CBC mode
void des_encrypt_CBC_mode(const string &plain, string &cipher, const bitset<48> *roundkey, const bitset<64> iv)
{
    // gán plain vào cipher
    cipher = plain;
    // padding cipher text
    PKCS5_padding(cipher);
    // số block encrypt
    int numberOfBlock = cipher.length() / 8;
    bitset<64> plainBlock;
    bitset<64> tmpBlock;
    bitset<64> cipherBlock;

    str_to_word64((uint8_t *)&cipher[0], plainBlock);
    plainBlock ^= iv;
    des_encrypt(plainBlock, cipherBlock, roundkey);
    word64_to_str(cipherBlock, (uint8_t *)&cipher[0]);
    tmpBlock = cipherBlock;

    for (int i = 1; i < numberOfBlock; ++i)
    {
        str_to_word64((uint8_t *)&cipher[i << 3], plainBlock);
        plainBlock ^= tmpBlock;
        des_encrypt(plainBlock, cipherBlock, roundkey);
        word64_to_str(cipherBlock, (uint8_t *)&cipher[i << 3]);
        tmpBlock = cipherBlock;
    }
}
// decrypt core thread
void des_decrypt_CBC_core(const char *cipher, char *recovered, const bitset<48> *roundkey, const bitset<64> iv, const int &nBlock)
{
    bitset<64> cipherBlock;
    bitset<64> tmpBlock;
    bitset<64> recoverBlock;
    str_to_word64((uint8_t *)&recovered[0], cipherBlock);
    des_decrypt(cipherBlock, recoverBlock, roundkey);
    recoverBlock ^= iv;
    word64_to_str(recoverBlock, (uint8_t *)&recovered[0]);
    tmpBlock = cipherBlock;
    for (int i = 1; i < nBlock; ++i)
    {
        str_to_word64((uint8_t *)&recovered[i << 3], cipherBlock);
        des_decrypt(cipherBlock, recoverBlock, roundkey);
        recoverBlock ^= tmpBlock;
        word64_to_str(recoverBlock, (uint8_t *)&recovered[i << 3]);
        tmpBlock = cipherBlock;
    }
}
// decrypt with CBC mode
void des_decrypt_CBC_mode(const string &cipher, string &recovered, const bitset<48> *roundkey, const bitset<64> iv)
{
    // gán plain vào cipher
    recovered = cipher;
    // số block encrypt
    int numberOfBlock = recovered.length() >> 3;
    // số thread
    int nThread = numberOfBlock >> 8;
    thread *decrypt_threads = new thread[nThread + 1];
    // biến tạm
    int j;
    // iv tạm
    bitset<64> tmp;
    // kiểm tra nếu số block < 256 thì k khởi tạo thread
    if (nThread)
    {
        // khởi tạo thread 0
        decrypt_threads[0] = thread(des_decrypt_CBC_core, (char *)&cipher[0], (char *)&recovered[0], roundkey, iv, 256);
        for (int i = 1; i < nThread; ++i)
        {
            // vị trí của recovered text được chuyền vào thread(i*256)
            j = i << 11;
            // khởi tạo thread
            str_to_word64((uint8_t *)&cipher[j - 8], tmp);
            decrypt_threads[i] = thread(des_decrypt_CBC_core, (char *)&cipher[j], (char *)&recovered[j], roundkey, tmp, 256);
        }
        // kiểm tra xem có thread thiếu hay k(block<256)
        if (numberOfBlock % 256)
        {
            // vị trí của recovered text của thread cuối (thread k đủ 256 block)
            j = nThread << 11;
            str_to_word64((uint8_t *)&cipher[j - 8], tmp);
            decrypt_threads[nThread] = thread(des_decrypt_CBC_core, (char *)&cipher[j], (char *)&recovered[j], roundkey, tmp, numberOfBlock % 256);
            ++nThread;
        }
        //phần lỗi
        for (int i = 0; i < nThread; ++i)
        {
            if (decrypt_threads[i].joinable())
                decrypt_threads[i].join();
        }
    }
    else
        des_decrypt_CBC_core((char *)&cipher[0], (char *)&recovered[0], roundkey, iv, numberOfBlock);
    de_PKCS5_padding(recovered);
    //giải phóng thread
    delete[] decrypt_threads;
}
// xóa các ký tự '\n'trong stdin
void DiscardLFFromStdin(const int &num)
{
    int tmp = num;
    int c;
    while (tmp--)
        while ((c = getwchar()) != '\n')
            if (c == WEOF)
                return;
}
// nhập key từ bàn phím
void InputKeyFromSreen(string &key)
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
    } while (int(wkey.length()) != 8);

    // chuyển wkey(wstring) về key(string)
    key = wstring_to_string(wkey);
}
// nhập plain từ bàn phím
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
// nhập iv,key từ file
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
// quá trình nhập các thông số plain,key,iv
void InputProcess(string &plain, string &key, string &iv)
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

    // chọn cách lấy key
    wcout << "1. From File AES_key.key\n";
    wcout << "2. From console (8 bytes)\n";
    wcout << "Select your key: ";
    wcin >> choice;
    switch (choice)
    {
    case 1:
        InputStringFromFile("AES_key.key", key, 8);
        break;
    case 2:
        InputKeyFromSreen(key);
        break;
    default:
        wcout << "What did you choose?\n";
        exit(-1);
    }

    // chọn cách lấy initial vector
    wcout << "1. From File AES_iv.key\n";
    wcout << "2. From console (8 bytes)\n";
    wcout << "Select your initial vector: ";
    wcin >> choice;
    switch (choice)
    {
    case 1:
        InputStringFromFile("AES_iv.key", iv, 8);
        break;
    case 2:
        InputKeyFromSreen(iv);
        break;
    default:
        wcout << "What did you choose?\n";
        exit(-1);
    }

    // hoàn thành nhập input
    wcout << "Input process succeeded\n";
    wcout << "---------------------\n";
}
// in ra input đã nhập
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

int main()
{
    IOSYNTAX;
    string plain, key, iv;
    InputProcess(plain, key, iv);
    OutputProcess(plain, key, iv);

    bitset<64> binkey, biniv;
    str_to_word64((uint8_t *)&key[0], binkey);
    str_to_word64((uint8_t *)&iv[0], biniv);
    string cipher, recovered;
    clock_t start, end;

    start = clock();
    for (int i = 0; i < 1000; ++i)
    {
        // tạo round key
        bitset<48> *roundkey = gernerate_key(binkey);
        // encrypt
        cipher.clear();
        des_encrypt_CBC_mode(plain, cipher, roundkey, biniv);
        delete[] roundkey;
    }
    end = clock();
    wcout << "Cipher text: " << string_to_wstring(text_to_hex(cipher)) << endl;
    // in thời gian thực hiện encrypt 1000 lần
    wcout << "Time for encryption (1 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;

    start = clock();
    for (int i = 0; i < 1000; ++i)
    {
        // tạo round key
        bitset<48> *roundkey = gernerate_key(binkey);
        // decrypt
        recovered.clear();
        des_decrypt_CBC_mode(cipher, recovered, roundkey, biniv);
        delete[] roundkey;
    }
    end = clock();
    // in kết quả recoverd
    wcout << "Recovered text: " << string_to_wstring(recovered) << endl;

    //in thời gian decrypt 1000 lần
    wcout << "Time for decryption (1 000 times): " << ((double)(end - start)) / CLOCKS_PER_SEC * 1000 << "ms" << endl;
}
