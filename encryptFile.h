#pragma once
namespace gzipEncrypt
{
	using namespace boost::filesystem;
	path compressEncryptDeleteFile(const path& filepath, const char* cpassword, int iter);
	path descrypt_path(path file, const char* password, int iter);
	void compute_dropbox_hash(path file, char* hash, int& hash_len);
	void compute_hash(const char* algorithm, path file, char* hash, int& hash_len);
}
