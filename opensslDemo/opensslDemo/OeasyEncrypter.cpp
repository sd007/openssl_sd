#include "OeasyEncrypter.h"
#include <assert.h>
using namespace Oeasy;

OeasyEncrypter::OeasyEncrypter()
{
	m_pPriFile = NULL;
	m_pPubFile = NULL;
	m_rsa = NULL;
	m_defaultPubFile = "public.pem";
	m_defaultPriFile = "private.pem";
	memset(m_iv, 0, AES_BLOCK_SIZE);
}

OeasyEncrypter::~OeasyEncrypter()
{
	RSA_free(m_rsa);
}

int OeasyEncrypter::SetAesKey( const unsigned char *userKey, int keylen, KeyType type)
{
	assert(userKey);
	assert(keylen <= 32);
	memset(m_iv, 0, AES_BLOCK_SIZE);
	if (type == Encrypt)
	{
		return AES_set_encrypt_key(userKey, keylen*8, &m_aesEncryptkey);
	}else if(type == Decrypt){
		return AES_set_decrypt_key(userKey, keylen*8, &m_aesDecryptkey);
	}
	
	cout<<"SetAesKey:KeyType ERROR!"<<endl;
	return -10;
}

int OeasyEncrypter::AesEncrypt( const unsigned char* src, int srclen, unsigned char* dst, int *dstLen, AESMode aesmode)
{
	assert(src && dst);
	int mode = srclen%16;
	int len = srclen;
	//16字节补齐处理
	if(mode > 0){
		len = srclen+(16-mode);
	}
	if (*dstLen < len)
	{
		cout<<"AesEncrypt:Dst space is not enough!"<<endl;
		return -1;
	}
	unsigned char *bufsrc = (unsigned char*)malloc(len);
	memset(bufsrc, 0x00, len);
	memcpy(bufsrc, src, srclen);
	if (aesmode == AESMode::ECB)
	{
		for (int i =0; i < len; i += 16)
		{
			AES_encrypt( bufsrc + i, dst+i, &m_aesEncryptkey);
		}
	}else{
		AES_cbc_encrypt(bufsrc, dst,
			len, &m_aesEncryptkey,
			m_iv, AES_ENCRYPT);
	}
	*dstLen = len;
	free(bufsrc);
	return 0;
}

int OeasyEncrypter::AesDecrypt( const unsigned char* src, int srclen, unsigned char* dst, int *dstLen, AESMode aesmode )
{
	assert(src && dst);
	int mode = srclen%16;
	if(mode != 0){
		cout<<"AESDecypt:src len error!"<<endl;
		return -1;
	}
	if (aesmode == AESMode::ECB){
		for (int i =0; i < srclen; i += 16)
		{
			AES_decrypt(src+i, dst+i, &m_aesDecryptkey);
		}
	}else{
		AES_cbc_encrypt(src, dst,
			srclen, &m_aesDecryptkey,
			m_iv, AES_DECRYPT);
	}
	*dstLen = srclen;
	return 0;
}

int OeasyEncrypter::GenerateRsaKey( int bits /*= 1024*/ )
{
	m_rsa = RSA_generate_key(bits,RSA_F4,NULL,NULL);
	if (m_rsa == NULL)
	{
		cout << "GenerateRsaKey:rsa_generate_key error" << endl;
		return -1;
	}
	//生成公钥证书文件
	if(m_pPubFile == NULL){ m_pPubFile = m_defaultPubFile;}
	const char* pubpath = m_pPubFile;
	BIO *pBio = BIO_new_file(pubpath,"wb");
	if (pBio == NULL)
	{
		cout << "GenerateRsaKey:BIO_new_file " << pubpath << " error" << endl;
		return -2;
	}
	if(PEM_write_bio_RSAPublicKey(pBio,m_rsa) == 0)
	{
		cout << "GenerateRsaKey:write public key error" << endl;
		return -3;
	}
	BIO_free_all(pBio);

	//生成私钥证书文件
	if(m_pPriFile == NULL){ m_pPriFile = m_defaultPriFile;}
	const char* pripath = m_pPriFile;
	pBio = BIO_new_file(pripath,"wb");
	if (pBio == NULL)
	{
		cout << "GenerateRsaKey:BIO_new_file " << pripath << " error" << endl;
		return -4;
	}
	if(PEM_write_bio_RSAPrivateKey(pBio,m_rsa,NULL,NULL,0,NULL,NULL) == 0)
	{
		cout << "GenerateRsaKey:write private key error" << endl;
		return -5;
	}
	BIO_free_all(pBio);
	return 0;
}

int OeasyEncrypter::RsaEncrypt( unsigned char* src, int srclen, unsigned char* dst, int *dstLen, RsaType type /*= publicKey*/  )
{
	assert(src && dst);
	BIO *pBio = NULL;
	if(type == privateKey)
	{
		pBio = BIO_new_file(m_pPriFile,"r");
		m_rsa = PEM_read_bio_RSAPrivateKey(pBio,NULL,NULL,NULL);
	}else{
		pBio = BIO_new_file(m_pPubFile,"r");
		m_rsa = PEM_read_bio_RSAPublicKey(pBio,NULL,NULL,NULL);
	}
	if (pBio == NULL){
		cout<<"RsaEncrypt:KeyFile not Exist!"<<endl;
		return -2;
	} 
	BIO_free_all(pBio);
	if(CheckRsaKey(m_rsa) <0) return -1;
	*dstLen = RSA_public_encrypt(
		(RSA_size(m_rsa)-11)>srclen?srclen:RSA_size(m_rsa)-11,
		reinterpret_cast<unsigned char*>(src),
		reinterpret_cast<unsigned char*>(dst),
		m_rsa,
		RSA_PKCS1_PADDING);
	if(*dstLen <= 0) 
	{
		cout<<"RsaEncrypt Failed!"<<endl;
		return -1;
	}
	return 0;
}

int OeasyEncrypter::RsaDecrypt( unsigned char* src, int srclen, unsigned char* dst, int *dstLen , RsaType type /*= publicKey*/ )
{
	assert(src && dst);
	BIO *pBio = NULL;
	if(type == privateKey)
	{
		pBio = BIO_new_file(m_pPriFile,"r");
		m_rsa = PEM_read_bio_RSAPrivateKey(pBio,NULL,NULL,NULL);
	}else{
		pBio = BIO_new_file(m_pPubFile,"r");
		m_rsa = PEM_read_bio_RSAPublicKey(pBio,NULL,NULL,NULL);
	}
	if (pBio == NULL){
		cout<<"RsaDecrypt:KeyFile not Exist!"<<endl;
		return -2;
	} 
	BIO_free_all(pBio);
	if(CheckRsaKey(m_rsa) <0) return -1;
	*dstLen = RSA_private_decrypt(
		RSA_size(m_rsa),
		reinterpret_cast<unsigned char*>(src),
		reinterpret_cast<unsigned char*>(dst),
		m_rsa,
		RSA_PKCS1_PADDING);
	if(*dstLen <= 0){
		cout<<"RsaDecrypt Failed!" <<endl;
		return -1;
	}
	return 0;
}

int OeasyEncrypter::CheckRsaKey(RSA *rsa)
{
	int r = RSA_check_key(rsa);
	if (r == 1)
	{
		cout<<"CheckRsaKey:RSA key ok"<<endl;
	} 
	else if (r == 0) 
	{
		unsigned long err;
		while ((err = ERR_peek_error()) != 0 &&
			ERR_GET_LIB(err) == ERR_LIB_RSA &&
			ERR_GET_FUNC(err) == RSA_F_RSA_CHECK_KEY &&
			ERR_GET_REASON(err) != ERR_R_MALLOC_FAILURE) {
				cout<<"CheckRsaKey：RSA key error: %s\n"<<ERR_reason_error_string(err);
				ERR_get_error(); /* remove e from error stack */
		}
	}
	else if (r == -1) 
	{
		cout<<"CheckRsaKey:error!"<<endl;
	}
	return r;
}

void OeasyEncrypter::SetRsaKeyFilePath( char* publicKeyPath, char* privateKeyPath )
{
	assert(publicKeyPath || privateKeyPath);
	m_pPriFile = privateKeyPath;
	m_pPubFile = publicKeyPath;
}

OeasyEncrypter& OeasyEncrypter::getInstance()
{
	//单例 C++0X以后，要求编译器保证内部静态变量的线程安全性，可以不加锁。但C++ 0X以前，仍需要加锁。
	static OeasyEncrypter instance;
	return instance;
}
