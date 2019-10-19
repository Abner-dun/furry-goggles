#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif 

#include <stdio.h>
#include <string.h>
#include <conio.h>
#include <windows.h>
#include <wincrypt.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define KEYLENGTH  0x00800000
void HandleError(char *s);
HCRYPTPROV GetCryptProv();

#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 


BOOL EncryptFile(
     PCHAR szSource, 
     PCHAR szDestination, 
     PCHAR szPassword); 

HCRYPTKEY GenKeyByPassword(HCRYPTPROV hCryptProv,PCHAR szPassword);
HCRYPTKEY GenKeyByRandom(HCRYPTPROV hCryptProv,FILE* hDestination);
 
//-------------------------------------------------------------------
// Begin main.

void main(void) 
{ 
    PCHAR szSource; 
    PCHAR szDestination; 
    CHAR szPassword[100] = ""; 
    char  response;
 
	if(!(szSource=(char *)malloc(100)))
		HandleError("Memory allocation failed.");
	if(!(szDestination=(char *)malloc(100)))
		HandleError("Memory allocation failed.");

	printf("加密一个文件. \n\n");
	printf("请输入需要被加密文件的名称: ");
	fgets(szSource, 100, stdin);
	if(szSource[strlen(szSource)-1] == '\n')
		 szSource[strlen(szSource)-1] = '\0';
	printf("请输入需要输出文件文件的名称: ");
	fgets(szDestination, 100, stdin);
	if(szDestination[strlen(szDestination)-1] == '\n')
		 szDestination[strlen(szDestination)-1] = '\0';
	printf("要使用密码对这个文件加密吗? ( y/n ) ");
	response = getchar();
	if(response == 'y')
	{
		printf("请输入密码:");
		getchar();
		gets(szPassword);
	}
	else
	{
		printf("密钥将生成但没有使用密码. \n");
	}

	//-------------------------------------------------------------------
	// 调用函数 EncryptFile 进行实际的加密操作.
 
	if(EncryptFile(szSource, szDestination, szPassword))
	{
		   printf("对文件 %s 的加密已经成功! \n", 
			   szSource);
		   printf("加密后的数据存储在文件 %s 中.\n",szDestination);
	}
	else
	{
		  HandleError("解密文件出错!"); 
	}
	//-------------------------------------------------------------------
	// 释放内存.
	if(szSource)
		 free(szSource);
	if(szDestination)
		 free(szDestination);

} // end main
 
//-------------------------------------------------------------------
// 功能：加密原文szSource文件，加密后的数据存储在szDestination文件中
// 参数:
//  szSource：原文文件名
//  szDestination：加密后数据存储文件
//  szPassword：用户输入的密码
static BOOL EncryptFile(
        PCHAR szSource, 
        PCHAR szDestination, 
        PCHAR szPassword)
{ 
	//-------------------------------------------------------------------
	// 变量申明与初始化.

	FILE *hSource; 
	FILE *hDestination; 

	HCRYPTPROV hCryptProv; 
	HCRYPTKEY hKey; 


	PBYTE pbBuffer; 
	DWORD dwBlockLen; 
	DWORD dwBufferLen; 
	DWORD dwCount; 
 
	//-------------------------------------------------------------------
	// 打开原文文件. 
	if(hSource = fopen(szSource,"rb"))
	{
	   printf("原文文件 %s 已经打开. \n", szSource);
	}
	else
	{ 
	   HandleError("打开原文文件出错!");
	} 

	//-------------------------------------------------------------------
	// 打开目标文件. 
	if(hDestination = fopen(szDestination,"wb"))
	{
		 printf("目标文件 %s 已经打开. \n", szDestination);
	}
	else
	{
		HandleError("打开目标文件出错!"); 
	}
	//获取加密服务者句柄
	hCryptProv = GetCryptProv();

	//-------------------------------------------------------------------
	// 创建会话密钥.
	if(!szPassword || strcmp(szPassword,"")==0 ) 
	{ 
     
		 //--------------------------------------------------------------
		 // 当输入密码为空时，则创建随机的加密密钥，并导出创建的密钥保存到文件中. 

		hKey = GenKeyByRandom( hCryptProv, hDestination);

		 
	} 
	else 
	{ 
		 //--------------------------------------------------------------
		 // 当输入密码不为空时，则通过输入密码创建加密密钥

		hKey=GenKeyByPassword( hCryptProv, szPassword);
		
	} 
 
	//--------------------------------------------------------------------
	// 因为加密算法按ENCRYPT_BLOCK_SIZE 大小块加密，所以被加密的
	// 数据长度必须是ENCRYPT_BLOCK_SIZE 的整数倍。下面计算一次加密的
	// 数据长度。

	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE; 

	//--------------------------------------------------------------------
	// 确定加密后密文数据块大小. 若是分组密码模式，则必须有容纳额外块的空间	

	if(ENCRYPT_BLOCK_SIZE > 1) 
		dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE; 
	else 
		dwBufferLen = dwBlockLen; 
    
	//-------------------------------------------------------------------
	// 分配内存空间. 
	if(pbBuffer = (BYTE *)malloc(dwBufferLen))
	{
		printf("已经为缓冲区分配了内存. \n");
	}
	else
	{ 
		HandleError("所需内存不够. \n"); 
	}

	//-------------------------------------------------------------------
	// 循环加密 原文件
	do 
	{ 

		//-------------------------------------------------------------------
		// 每次从原文件中读取dwBlockLen字节数据. 
		dwCount = fread(pbBuffer, 1, dwBlockLen, hSource); 
		if(ferror(hSource))
		{ 
			HandleError("读取明文文件出错!\n");
		}
 
		//-------------------------------------------------------------------
		// 加密数据. 
		if(!CryptEncrypt(
			hKey,			//密钥
			0,				//如果数据同时进行散列和加密，这里传入一个散列对象
			feof(hSource),	//如果是最后一个被加密的块，输入TRUE.如果不是输入FALSE.
							//这里通过判断是否到文件尾来决定是否为最后一块。
			0,				//保留
			pbBuffer,		//输入被加密数据，输出加密后的数据
			&dwCount,		//输入被加密数据实际长度，输出加密后数据长度
			dwBufferLen))	//pbBuffer的大小。
		{ 
		   HandleError("Error during CryptEncrypt. \n"); 
		} 

		//-------------------------------------------------------------------
		// 把加密后数据写到密文文件中 

		fwrite(pbBuffer, 1, dwCount, hDestination); 
		if(ferror(hDestination))
		{ 
			HandleError("写入密文时出错.");
		}

	} 	while(!feof(hSource)); 

	//-------------------------------------------------------------------
	// 关闭文件

	if(hSource)
	{
		if(fclose(hSource))
			HandleError("关闭原文文件出错!");
	}
	if(hDestination)
	{
		if(fclose(hDestination))
			HandleError("关闭目标文件出错!");
	}

	//-------------------------------------------------------------------
	// 释放内存空间. 

	if(pbBuffer) 
		 free(pbBuffer); 
 
	//-------------------------------------------------------------------
	// 销毁会话密钥

	if(hKey)
	{
		if(!(CryptDestroyKey(hKey)))
			HandleError("Error during CryptDestroyKey");
	}

	//-------------------------------------------------------------------
	// 释放CSP句柄

	if(hCryptProv)
	{
		if(!(CryptReleaseContext(hCryptProv, 0)))
			HandleError("Error during CryptReleaseContext");
	}
	return(TRUE); 
} // end Encryptfile


//获取加密提供者句柄
HCRYPTPROV GetCryptProv()
{
	HCRYPTPROV hCryptProv;                      // 加密服务提供者句柄
	
	//获取加密提供者句柄
	if(CryptAcquireContext(
				&hCryptProv,         // 加密服务提供者句柄
				NULL,                // 密钥容器名,这里使用登陆用户名
				MS_ENHANCED_PROV,         // 加密服务提供者     
				PROV_RSA_FULL,       // 加密服务提供者类型,可以提供加密和签名等功能
				0))                  // 标志
	{
		printf("加密服务提供者句柄获取成功!\n");
	}
	else
	{
		
  
		//重新建立一个新的密钥集
	    if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
		{
		   HandleError("重新建立一个新的密钥集出错!");
		}
 
	}
	return hCryptProv;
}


//  HandleError：错误处理函数，打印错误信息，并退出程序
void HandleError(char *s)
{
    printf("程序执行发生错误!\n");
    printf("%s\n",s);
    printf("错误代码为: %x.\n",GetLastError());
    printf("程序终止执行!\n");
    exit(1);
}


// GenKeyByRandom：通过随机数创建会话密钥
// 参数：hCryptProv CSP句柄
//       hDestination 目标文件，导出的会话密钥保存在此文件中
HCRYPTKEY GenKeyByRandom(HCRYPTPROV hCryptProv,FILE* hDestination)
{
	HCRYPTKEY hKey; 
	HCRYPTKEY hXchgKey; 

	PBYTE pbKeyBlob; 
	DWORD dwKeyBlobLen; 

	if(CryptGenKey(
		  hCryptProv, 
		  ENCRYPT_ALGORITHM, 
		  KEYLENGTH | CRYPT_EXPORTABLE, 
		  &hKey))
	  {
		  printf("一个会话密钥已经被创建. \n");
	  } 
	  else
	  {
		  HandleError("Error during CryptGenKey. \n"); 
	  }
	 //--------------------------------------------------------------
	   // 创建交换密钥
	   if(CryptGenKey(
		   hCryptProv,
		   AT_KEYEXCHANGE,
		   0,
		   &hXchgKey)) 
	   {
		   printf("交换密钥对已经创建.\n");
	   }
	   else
	   {
		  HandleError("在试图创建交换密钥时出错.\n");
	   }

	 //--------------------------------------------------------------
	 // 确定密钥数据块长度，并分配空间. 

	 if(CryptExportKey(
		   hKey, 
		   hXchgKey, 
		   SIMPLEBLOB, 
		   0, 
		   NULL, 
		   &dwKeyBlobLen))
	 {
		   printf("此密钥块的长度是 %d 字节. \n",dwKeyBlobLen);
	   }
	   else
	   {  
			HandleError("计算密钥数据块长度出错! \n");
	   }
	   if(pbKeyBlob =(BYTE *)malloc(dwKeyBlobLen))
	   { 
		  printf("已经问此密钥块分配了内存. \n");
	   }
	   else
	   { 
		  HandleError("所需内存不够. \n"); 
	   }
	 //--------------------------------------------------------------
	 // 导出会话密钥到简单密钥数据块中. 
 
	 if(CryptExportKey(
		  hKey, 
		  hXchgKey, 
		  SIMPLEBLOB, 
		  0, 
		  pbKeyBlob, 
		  &dwKeyBlobLen))
	   {
		   printf("此会话密钥已经被导出. \n");
	   } 
	   else
	   {
		   HandleError("Error during CryptExportKey!\n");
	   } 
	 //--------------------------------------------------------------
	 //释放交换密钥句柄. 

	 if(hXchgKey)
	 {
		  if(!(CryptDestroyKey(hXchgKey)))
			   HandleError("Error during CryptDestroyKey"); 

		  hXchgKey = 0;
	 }

	 //--------------------------------------------------------------
	 // 写密钥块长度到目标文件. 

	 fwrite(&dwKeyBlobLen, sizeof(DWORD), 1, hDestination); 
	 if(ferror(hDestination))
	 { 
		 HandleError("写密钥块长度出错.");
	 }
	 else
	 {
		 printf("密钥块长度已经被写入. \n");
	 }
	 //--------------------------------------------------------------
	 //写密钥块数据到目标文件. 
 
	 fwrite(pbKeyBlob, 1, dwKeyBlobLen, hDestination); 
	 if(ferror(hDestination))
	 { 
		HandleError("写密钥数据出错");
	 }
	 else
	 {
		printf("此密钥块数据已经被写入目标文件. \n");
	 }
	 // 释放内存空间.
	 free(pbKeyBlob);
	 //返回创建的会话密钥
	 return hKey;
}

// GenKeyByRandom：通过输入密码创建会话密钥
// 参数：hCryptProv CSP句柄
//       szPassword 输入密码
HCRYPTKEY GenKeyByPassword(HCRYPTPROV hCryptProv,PCHAR szPassword)
{
	HCRYPTKEY hKey; 
	HCRYPTHASH hHash;
	//-------------------------------------------------------------------
	// 创建哈希句柄. 

	if(CryptCreateHash(
		   hCryptProv, 
		   CALG_MD5, 
		   0, 
		   0, 
		   &hHash))
		{
			printf("一个哈希句柄已经被创建. \n");
		}
		else
		{ 
			 HandleError("Error during CryptCreateHash!\n");
		}  
	//-------------------------------------------------------------------
	// 计算输入密码的哈希值. 

	if(CryptHashData(
		   hHash, 
		   (BYTE *)szPassword, 
		   strlen(szPassword), 
		   0))
	 {
		printf("密码已经被添加到了哈希表中. \n");
	 }
	 else
	 {
		HandleError("Error during CryptHashData. \n"); 
	 }
	//-------------------------------------------------------------------
	// 通过哈希值创建会话密钥. 

	if(CryptDeriveKey(
		   hCryptProv, 
		   ENCRYPT_ALGORITHM, 
		   hHash, 
		   KEYLENGTH, 
		   &hKey))
	 {
	   printf("通过密码的哈希值获得了加密密钥. \n"); 
	 }
	 else
	 {
	   HandleError("Error during CryptDeriveKey!\n"); 
	 }
	//-------------------------------------------------------------------
	// 销毁哈希句柄. 

	if(hHash) 
	{
		if(!(CryptDestroyHash(hHash)))
		   HandleError("Error during CryptDestroyHash"); 
		hHash = 0;
	}

	//返回创建的会话密钥
	return hKey;
}
