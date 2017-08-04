#ifndef OEASY_OEASYENCRYPTER
#define OEASY_OEASYENCRYPTER

#include <iostream>

using namespace std;
extern "C"
{
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include  <openssl/err.h>
};

/************************************************************************/
/* 基于openssl 1.1.0e版本对AES，RSA加密的封装实现
   @Author sd
   @Data 2017-4-25
   @notice 
   AES加密明文和密文长度一致，注意必须16字节对齐。AES算法的数据分组长度为128比特、密钥长度为128/192/256比特，即不能超过32字节
   RSA算法每次可加解密的字节长度是受密钥长度限制的，每次最多能加密的字节数是RSA_size(公钥)减去11个字节
*/
/************************************************************************/

namespace Oeasy{
class OeasyEncrypter
{
public:
	//单例模式，线程安全
	static OeasyEncrypter& getInstance();
	~OeasyEncrypter();
	//AES加解密
	enum KeyType{ //区分加密解密
		Encrypt,
		Decrypt
	};
	enum AESMode{ //区分加密解密
		ECB,
		CBC
	};
	//设置AES秘钥长度，密钥唯一，加密或解密前设置，keylen <= 32
	int SetAesKey(const unsigned char *userKey, int keylen, KeyType type);
	//AES加密函数（16字节对其），注：src长度srclen为16的倍数
	int AesEncrypt(const unsigned char* src, int srclen, unsigned char* dst, int *dstLen, AESMode mode = ECB);
	//AES解密函数
	int AesDecrypt(const unsigned char* src, int srclen, unsigned char* dst, int *dstLen, AESMode mode = ECB);

	//RSA加解密
	enum RsaType{ //区分公钥私钥
		publicKey,
		privateKey
	};
	//设置加密或解密证书文件存放/读取路径
	void SetRsaKeyFilePath(char* publicKeyPath, char* privateKeyPath);
	//生成RSA公钥私钥对，保存证书文件到setRsaKeyFilePath设置的路径，默认当前路径
	int GenerateRsaKey(int bits = 1024);
	//RSA加密函数 
	//generateRsaKey参数为1024bit时，计算字节为1024/8 = 128，则每次加密的最大字节为 128-11 = 117
	//type 使用公钥或私钥进行加密,默认公钥加密
	//注：加密后dst长度不小于128字节
	int RsaEncrypt(unsigned char* src, int srclen, unsigned char* dst, int *dstLen, RsaType type = publicKey);
	//RSA解密函数,解密长度为RSA_size(m_rsa)
	//type 使用公钥或私钥进行解密,默认私钥解密
	int RsaDecrypt(unsigned char* src, int srclen, unsigned char* dst, int *dstLen, RsaType type = privateKey);

protected:
	int CheckRsaKey(RSA *rsa);
private:
	OeasyEncrypter(); 
	
private:
	//AESkey,此处针对加密，解密分别存储密钥，本质上是相同的
	AES_KEY m_aesEncryptkey;
	AES_KEY m_aesDecryptkey;
	//aes加密的初始化向量
	unsigned char m_iv[AES_BLOCK_SIZE];

	//RSA密钥
	RSA *m_rsa;
	//默认的公钥私钥路径
	char *m_defaultPubFile;
	char *m_defaultPriFile;
	//公钥私钥路径
	char *m_pPubFile;
	char *m_pPriFile;
};

};

#endif //OEASY_OEASYENCRYPTER
