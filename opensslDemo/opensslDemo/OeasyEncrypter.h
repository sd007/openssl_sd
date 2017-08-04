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
/* ����openssl 1.1.0e�汾��AES��RSA���ܵķ�װʵ��
   @Author sd
   @Data 2017-4-25
   @notice 
   AES�������ĺ����ĳ���һ�£�ע�����16�ֽڶ��롣AES�㷨�����ݷ��鳤��Ϊ128���ء���Կ����Ϊ128/192/256���أ������ܳ���32�ֽ�
   RSA�㷨ÿ�οɼӽ��ܵ��ֽڳ���������Կ�������Ƶģ�ÿ������ܼ��ܵ��ֽ�����RSA_size(��Կ)��ȥ11���ֽ�
*/
/************************************************************************/

namespace Oeasy{
class OeasyEncrypter
{
public:
	//����ģʽ���̰߳�ȫ
	static OeasyEncrypter& getInstance();
	~OeasyEncrypter();
	//AES�ӽ���
	enum KeyType{ //���ּ��ܽ���
		Encrypt,
		Decrypt
	};
	enum AESMode{ //���ּ��ܽ���
		ECB,
		CBC
	};
	//����AES��Կ���ȣ���ԿΨһ�����ܻ����ǰ���ã�keylen <= 32
	int SetAesKey(const unsigned char *userKey, int keylen, KeyType type);
	//AES���ܺ�����16�ֽڶ��䣩��ע��src����srclenΪ16�ı���
	int AesEncrypt(const unsigned char* src, int srclen, unsigned char* dst, int *dstLen, AESMode mode = ECB);
	//AES���ܺ���
	int AesDecrypt(const unsigned char* src, int srclen, unsigned char* dst, int *dstLen, AESMode mode = ECB);

	//RSA�ӽ���
	enum RsaType{ //���ֹ�Կ˽Կ
		publicKey,
		privateKey
	};
	//���ü��ܻ����֤���ļ����/��ȡ·��
	void SetRsaKeyFilePath(char* publicKeyPath, char* privateKeyPath);
	//����RSA��Կ˽Կ�ԣ�����֤���ļ���setRsaKeyFilePath���õ�·����Ĭ�ϵ�ǰ·��
	int GenerateRsaKey(int bits = 1024);
	//RSA���ܺ��� 
	//generateRsaKey����Ϊ1024bitʱ�������ֽ�Ϊ1024/8 = 128����ÿ�μ��ܵ�����ֽ�Ϊ 128-11 = 117
	//type ʹ�ù�Կ��˽Կ���м���,Ĭ�Ϲ�Կ����
	//ע�����ܺ�dst���Ȳ�С��128�ֽ�
	int RsaEncrypt(unsigned char* src, int srclen, unsigned char* dst, int *dstLen, RsaType type = publicKey);
	//RSA���ܺ���,���ܳ���ΪRSA_size(m_rsa)
	//type ʹ�ù�Կ��˽Կ���н���,Ĭ��˽Կ����
	int RsaDecrypt(unsigned char* src, int srclen, unsigned char* dst, int *dstLen, RsaType type = privateKey);

protected:
	int CheckRsaKey(RSA *rsa);
private:
	OeasyEncrypter(); 
	
private:
	//AESkey,�˴���Լ��ܣ����ֱܷ�洢��Կ������������ͬ��
	AES_KEY m_aesEncryptkey;
	AES_KEY m_aesDecryptkey;
	//aes���ܵĳ�ʼ������
	unsigned char m_iv[AES_BLOCK_SIZE];

	//RSA��Կ
	RSA *m_rsa;
	//Ĭ�ϵĹ�Կ˽Կ·��
	char *m_defaultPubFile;
	char *m_defaultPriFile;
	//��Կ˽Կ·��
	char *m_pPubFile;
	char *m_pPriFile;
};

};

#endif //OEASY_OEASYENCRYPTER
