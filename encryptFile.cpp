// EVP-encrypt.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <string>
#include <vector>
#include <memory>
#include <limits>
#include <stdexcept>
#include <cstdlib>
#include <cstdio>
#include <cstring>
//
#include <boost/locale.hpp>
#include <boost/filesystem.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/filter/gzip.hpp>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include "derivateKey.h"
#include "encryptFile.h"
//
const int BLOCKSIZE = 4 * 1024 * 1024;
//
static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;
static const unsigned int AES_SALT_SIZE = 8;
static const unsigned int BUFSIZE = 1024;
template <typename T>
struct zallocator
{
public:
    typedef T value_type;
    typedef value_type* pointer;
    typedef const value_type* const_pointer;
    typedef value_type& reference;
    typedef const value_type& const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;

    pointer address(reference v) const { return &v; }
    const_pointer address(const_reference v) const { return &v; }

    pointer allocate(size_type n, const void* hint = 0) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T))
            throw std::bad_alloc();
        return static_cast<pointer> (::operator new (n * sizeof(value_type)));
    }

    void deallocate(pointer p, size_type n) {
        OPENSSL_cleanse(p, n * sizeof(T));
        ::operator delete(p);
    }

    size_type max_size() const {
        return std::numeric_limits<size_type>::max() / sizeof(T);
    }

    template<typename U>
    struct rebind
    {
        typedef zallocator<U> other;
    };

    void construct(pointer ptr, const T& val) {
        new (static_cast<T*>(ptr)) T(val);
    }

    void destroy(pointer ptr) {
        static_cast<T*>(ptr)->~T();
    }

#if __cpluplus >= 201103L
    template<typename U, typename... Args>
    void construct(U* ptr, Args&&  ... args) {
        ::new (static_cast<void*> (ptr)) U(std::forward<Args>(args)...);
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }
#endif
};

typedef unsigned char byte;
typedef struct _cipher_params_t {
    byte* salt;
    byte* key;
    byte* iv;
    int encrypt;
    const EVP_CIPHER* cipher_type;
}cipher_params_t;
typedef std::basic_string<char, std::char_traits<char>, zallocator<char> > secure_string;
using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
using namespace boost::filesystem;
using namespace gzipEncrypt;
void error(const char* msg);
path encrypt_path(path filename, const char* secret, const int iter);
void file_encrypt_decrypt(cipher_params_t* params, boost::filesystem::ifstream& ifp, boost::filesystem::ofstream& ofp) {
    byte in_buf[BUFSIZE], out_buf[BUFSIZE + EVP_MAX_BLOCK_LENGTH];
    int num_bytes_read, out_len;
    EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
    if (params->encrypt == 1)
    {
        int rc = EVP_EncryptInit_ex(ctx.get(), params->cipher_type, NULL, params->key, params->iv);
        if (rc != 1)
            throw std::runtime_error("EVP_EncryptInit_ex failed");

        while (1) {
            // Read in data in blocks until EOF. Update the ciphering with each read.
            num_bytes_read = BUFSIZE;
            ifp.read(reinterpret_cast<char*>(in_buf), num_bytes_read);
            num_bytes_read = ifp.gcount();
            rc = EVP_EncryptUpdate(ctx.get(), out_buf, &out_len, in_buf, num_bytes_read);
            if (rc != 1)
                throw std::runtime_error("EVP_EncryptUpdate failed");
            ofp.write(reinterpret_cast<char*>(out_buf), out_len);

            if (num_bytes_read < BUFSIZE)
                break;
        }
        rc = EVP_EncryptFinal_ex(ctx.get(), out_buf, &out_len);
        if (rc != 1)
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        ofp.write(reinterpret_cast<char*>(out_buf), out_len);
    }
    else
    {
        int rc = EVP_DecryptInit_ex(ctx.get(), params->cipher_type, NULL, params->key, params->iv);
        if (rc != 1)
            throw std::runtime_error("EVP_DecryptInit_ex failed");

        while (1) {
            // Read in data in blocks until EOF. Update the ciphering with each read.
            num_bytes_read = BUFSIZE;
            ifp.read(reinterpret_cast<char*>(in_buf), num_bytes_read);
            num_bytes_read = ifp.gcount();
            rc = EVP_DecryptUpdate(ctx.get(), out_buf, &out_len, in_buf, num_bytes_read);
            if (rc != 1)
                throw std::runtime_error("EVP_DecryptUpdate failed");
            ofp.write(reinterpret_cast<char*>(out_buf), out_len);
            if (num_bytes_read < BUFSIZE)
                break;
        }
        rc = EVP_DecryptFinal_ex(ctx.get(), out_buf, &out_len);
        if (rc != 1)
            throw std::runtime_error("EVP_DecryptFinal_ex failed");
        ofp.write(reinterpret_cast<char*>(out_buf), out_len);
    }

}

/*void error(const char* msg)
{
    throw std::runtime_error(msg);
}*/

path encrypt_path(path file, const char* password, int iter)
{

    unsigned char signature[] = "Salted__";
    byte key[KEY_SIZE], iv[BLOCK_SIZE], salt[AES_SALT_SIZE];

    if (1 != RAND_bytes_ex(NULL, salt, AES_SALT_SIZE))
    {
        throw std::runtime_error("ERROR: RAND_bytes_ex\n");
    }

    if (!(EVPKeyderivation(password, (byte*)key, (byte*)iv, (byte*)salt, iter) == 0))
    {
        throw std::runtime_error("ERROR: key derivation  error\n");
    }
    cipher_params_t param;
    cipher_params_t* params;
    params = &param;
    params->key = key;
    params->iv = iv;
    params->salt = salt;

    /* Indicate that we want to encrypt */
    params->encrypt = 1;

    /* Set the cipher type you want for encryption-decryption */
    params->cipher_type = EVP_aes_256_cbc();

    ifstream f_input(file, std::ios_base::binary);
    path encrypted_path(file);
    encrypted_path += ".enc";
    ofstream f_enc(encrypted_path, std::ios_base::trunc | std::ios_base::binary);
    f_enc.write(reinterpret_cast<char*>(signature), AES_SALT_SIZE);
    f_enc.write(reinterpret_cast<char*>(salt), AES_SALT_SIZE);
    file_encrypt_decrypt(params, f_input, f_enc);
    f_input.close();
    f_enc.close();

    return encrypted_path;

}


path gzipEncrypt::descrypt_path(path file, const char* password, int iter)
{

    unsigned char signature[] = "Salted__";
    byte key[KEY_SIZE], iv[BLOCK_SIZE], salt[AES_SALT_SIZE];
    ifstream f_input(file, std::ios_base::binary);
    f_input.read(reinterpret_cast<char*>(signature), AES_SALT_SIZE);
    f_input.read(reinterpret_cast<char*>(salt), AES_SALT_SIZE);

    if (!(EVPKeyderivation(password, (byte*)key, (byte*)iv, (byte*)salt, iter) == 0))
    {
        throw std::runtime_error("ERROR: key derivation  error\n");
    }
    cipher_params_t param;
    cipher_params_t* params;
    params = &param;
    params->key = key;
    params->iv = iv;
    params->salt = salt;

    /* Indicate that we want to descrypt */
    params->encrypt = 0;

    /* Set the cipher type you want for encryption-decryption */
    params->cipher_type = EVP_aes_256_cbc();

    path descrypted_path(file);
    descrypted_path += ".des";
    ofstream f_enc(descrypted_path, std::ios_base::trunc | std::ios_base::binary);
    file_encrypt_decrypt(params, f_input, f_enc);
    f_input.close();
    f_enc.close();

    return descrypted_path;

}


path gzipEncrypt::compressEncryptDeleteFile(const path& filepath, const char* cpassword, int iter)
{
    using namespace std;
    using namespace boost::filesystem;
    vector<string> arc_extns{ ".zip",".jar",".7z",".rar",".dt",".tar",".arj",".gzip",".ace" };
    path compressedFileName(filepath);
    bool delete_compressed_file = false;
    if (!compressedFileName.has_extension() || find(arc_extns.begin(), arc_extns.end(), compressedFileName.extension().filename()) == arc_extns.end())
    {
        compressedFileName += ".gz";
        namespace bio = boost::iostreams;

        boost::filesystem::ifstream ifs(filepath, std::ios_base::in | std::ios_base::binary);
        ifs.seekg(0, std::ios_base::beg);
        boost::filesystem::ofstream ofile(compressedFileName, std::ios_base::out | std::ios_base::binary);
        bio::filtering_ostreambuf out;
        out.set_auto_close(true);
        out.push(bio::gzip_compressor(bio::gzip_params(bio::gzip::best_compression)));
        out.push(ofile);
        bio::copy(ifs, out);
        out.pop();
        bio::close(out);
        ifs.close();
        if (ofile.is_open())
            ofile.close();
        delete_compressed_file = true;
    }
    compressedFileName.make_preferred();

    path cencrypted_filename = encrypt_path(compressedFileName, cpassword, iter);
    if (delete_compressed_file)
        boost::filesystem::remove(compressedFileName);
    return cencrypted_filename;
}

int calculate_hashes_len(const path file)
{
    auto fsize = file_size(file);
    int digests_maxlen = (fsize / BLOCKSIZE + (fsize % BLOCKSIZE ? 1 : 0)) * EVP_MAX_MD_SIZE;
    return digests_maxlen;
}
void gzipEncrypt::compute_dropbox_hash(path file, char* hash, int& hash_len)
{
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;
    int rc;
    md = EVP_get_digestbyname("SHA256");
    if (md == NULL) {
        throw std::runtime_error("Unknown message digest");
    }
    if (!exists(file))
        throw std::runtime_error("file not found");
    ifstream f_input(file, std::ios_base::binary);
    int hashes_maxlen = calculate_hashes_len(file);
    unsigned char* hashes = new unsigned char[hashes_maxlen];
    int hashes_len = 0;
    unsigned int len = 0;
    while (1)
    {
        md = EVP_get_digestbyname("SHA256");
        if (md == NULL) {
            throw std::runtime_error("Unknown message digest");
        }
        mdctx = EVP_MD_CTX_new();
        rc = EVP_DigestInit_ex2(mdctx, md, NULL);
        if (rc != 1)
            throw std::runtime_error("EVP_DigestInit_ex2 error");
        char* buf = new char[BLOCKSIZE]();
        int num_bytes_read = BLOCKSIZE;
        f_input.read(buf, num_bytes_read);
        num_bytes_read = f_input.gcount();
        rc = EVP_DigestUpdate(mdctx, buf, num_bytes_read);
        if (rc != 1)
            throw std::runtime_error("EVP_DigestUpdate error");
        delete[]buf;
        unsigned char* p = hashes + hashes_len;
        rc = EVP_DigestFinal_ex(mdctx, p, &len);
        if (rc != 1)
            throw std::runtime_error("EVP_DigestFinal_ex error");
        EVP_MD_CTX_free(mdctx);
        hashes_len += len;
        if (num_bytes_read < BLOCKSIZE)
            break;
    }
    f_input.close();

    md = EVP_get_digestbyname("SHA256");
    if (md == NULL) {
        throw std::runtime_error("Unknown message digest");
    }
    mdctx = EVP_MD_CTX_new();
    rc = EVP_DigestInit_ex2(mdctx, md, NULL);
    if (rc != 1)
        throw std::runtime_error("EVP_DigestInit_ex2 error");
    rc = EVP_DigestUpdate(mdctx, hashes, hashes_len);
    if (rc != 1)
        throw std::runtime_error("EVP_DigestUpdate error");
    rc = EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    if (rc != 1)
        throw std::runtime_error("EVP_DigestFinal_ex error");
    EVP_MD_CTX_free(mdctx);
    delete[]hashes;
    int j = 0;
    for (unsigned int i = 0; i < md_len; i++)
        j += sprintf_s(hash + j, hash_len - j, "%02x", md_value[i]);

    hash_len = j;
}

void gzipEncrypt::compute_hash(const char* algorithm,path file, char* hash, int& hash_len)
{
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;
    int rc;
    md = EVP_get_digestbyname(algorithm);
    if (md == NULL) {
        throw std::runtime_error("Unknown message digest");
    }
    mdctx = EVP_MD_CTX_new();
    rc = EVP_DigestInit_ex2(mdctx, md, NULL);
    if (rc != 1)
        throw std::runtime_error("EVP_DigestInit_ex2 error");
    char* buf = new char[BLOCKSIZE]();
    int num_bytes_read = BLOCKSIZE;

    if (!exists(file))
        throw std::runtime_error("file not found");
    ifstream f_input(file, std::ios_base::binary);
    int hashes_maxlen = calculate_hashes_len(file);
    unsigned char* hashes = new unsigned char[hashes_maxlen];
    int hashes_len = 0;
    unsigned int len = 0;
    while (1)
    {
        f_input.read(buf, num_bytes_read);
        num_bytes_read = f_input.gcount();
        rc = EVP_DigestUpdate(mdctx, buf, num_bytes_read);
        if (rc != 1)
            throw std::runtime_error("EVP_DigestUpdate error");
        if (num_bytes_read < BLOCKSIZE)
            break;
    }
    rc = EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    if (rc != 1)
        throw std::runtime_error("EVP_DigestFinal_ex error");
    EVP_MD_CTX_free(mdctx);
    f_input.close();
    int j = 0;
    for (int i = 0; i < md_len; i++)
        j += sprintf_s(hash + j, hash_len - j, "%02x", md_value[i]);
    hash_len = j;

}
