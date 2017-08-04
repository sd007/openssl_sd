#include <iostream>
#include <stdio.h>
#include "OeasyEncrypter.h"

using namespace std;
using namespace Oeasy;

#define BUFSIZE 256

int main()
{
	//AES加解密
	cout<<"AES------------------------------------------------------------------"<<endl;
	unsigned char srcstr[BUFSIZE];
	unsigned char srctemp[BUFSIZE];
	memset(srctemp, 0, BUFSIZE);
	memset(srcstr, 0, BUFSIZE);	
	FILE *fp = fopen("d:/test.h264","r");
	if (fp)
	{
		fseek(fp,108, 1);
		fread(srcstr, BUFSIZE, 1, fp);
	}
	fclose(fp);
	memcpy(srctemp, srcstr, BUFSIZE);
	unsigned char detstr[BUFSIZE];
	memset(detstr, 0, BUFSIZE);
	unsigned char key[32];
	memset(key, 0, 32);
	for (int i = 0;i < 32; i++)
	{
		key[i] = i+10;
	}
	OeasyEncrypter::getInstance().SetAesKey(key, 32, OeasyEncrypter::Encrypt);
	int dstlen = BUFSIZE;
	cout<<"srcstr=:"<<endl;
	cout<<srcstr<<endl;

//	OeasyEncrypter::getInstance().AesEncrypt(srcstr, BUFSIZE, detstr, &dstlen, OeasyEncrypter::ECB);
	OeasyEncrypter::getInstance().AesEncrypt(srcstr, BUFSIZE, detstr, &dstlen, OeasyEncrypter::CBC);
	cout<<"AESEncrypt==:"<<endl;
	cout<<detstr<<endl;
	OeasyEncrypter::getInstance().SetAesKey(key, 32, OeasyEncrypter::Decrypt);
	dstlen = BUFSIZE;
	memset(srcstr, 0, BUFSIZE);
	OeasyEncrypter::getInstance().AesDecrypt(detstr, BUFSIZE, srcstr, &dstlen, OeasyEncrypter::CBC);
//	OeasyEncrypter::getInstance().AesDecrypt(detstr, BUFSIZE, srcstr, &dstlen, OeasyEncrypter::ECB);
	cout<<"AESDecrypt==:"<<endl;
	cout<<srcstr<<endl;
	cout<<"AESDecrypt len = :"<<dstlen<<endl;
	for (int i = 0;i <BUFSIZE;i++ )
	{
		if(srctemp[i] != srcstr[i]){

			cout<<"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"<<endl;
			break;
		}
	}

	//RSA加解密
	cout<<endl;
	cout<<"RSA------------------------------------------------------------------"<<endl;
	int ret1 = OeasyEncrypter::getInstance().GenerateRsaKey();
	cout<<"generateRsaKey ret =="<<ret1<<endl;
	unsigned char msgkey[32];
	memset(msgkey, 0, 32);
	for (int i = 0;i < 31; i++)
	{
		msgkey[i] = 50;
	}
	int ret = -1;
	cout<<"srckey==:"<<msgkey<<endl;
	unsigned char dstkey[256];
	memset(dstkey, 0, 256);
	int dstLen = 256;
	ret = OeasyEncrypter::getInstance().RsaEncrypt(msgkey, 32, dstkey,&dstLen);
	if(ret < 0)
	{
		cout<<"RSA Enc ERROR!";
		return 0;
	}
	cout<<"dstkey==:"<<dstkey<<"----len =:"<<dstLen<<endl;

	int newDstLen = dstLen;
	unsigned char newkey[256] = {0};
	memset(newkey, 0, 256);
	int newlen = 256;
	ret = OeasyEncrypter::getInstance().RsaDecrypt(dstkey, newDstLen, newkey, &newlen);
	if(ret < 0)
	{
		cout<<"RSA dec ERROR!";
		return 0;
	}
	cout<<"newkey==:"<<newkey<<endl;

	return 0;
}