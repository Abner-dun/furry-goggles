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

	printf("����һ���ļ�. \n\n");
	printf("��������Ҫ�������ļ�������: ");
	fgets(szSource, 100, stdin);
	if(szSource[strlen(szSource)-1] == '\n')
		 szSource[strlen(szSource)-1] = '\0';
	printf("��������Ҫ����ļ��ļ�������: ");
	fgets(szDestination, 100, stdin);
	if(szDestination[strlen(szDestination)-1] == '\n')
		 szDestination[strlen(szDestination)-1] = '\0';
	printf("Ҫʹ�����������ļ�������? ( y/n ) ");
	response = getchar();
	if(response == 'y')
	{
		printf("����������:");
		getchar();
		gets(szPassword);
	}
	else
	{
		printf("��Կ�����ɵ�û��ʹ������. \n");
	}

	//-------------------------------------------------------------------
	// ���ú��� EncryptFile ����ʵ�ʵļ��ܲ���.
 
	if(EncryptFile(szSource, szDestination, szPassword))
	{
		   printf("���ļ� %s �ļ����Ѿ��ɹ�! \n", 
			   szSource);
		   printf("���ܺ�����ݴ洢���ļ� %s ��.\n",szDestination);
	}
	else
	{
		  HandleError("�����ļ�����!"); 
	}
	//-------------------------------------------------------------------
	// �ͷ��ڴ�.
	if(szSource)
		 free(szSource);
	if(szDestination)
		 free(szDestination);

} // end main
 
//-------------------------------------------------------------------
// ���ܣ�����ԭ��szSource�ļ������ܺ�����ݴ洢��szDestination�ļ���
// ����:
//  szSource��ԭ���ļ���
//  szDestination�����ܺ����ݴ洢�ļ�
//  szPassword���û����������
static BOOL EncryptFile(
        PCHAR szSource, 
        PCHAR szDestination, 
        PCHAR szPassword)
{ 
	//-------------------------------------------------------------------
	// �����������ʼ��.

	FILE *hSource; 
	FILE *hDestination; 

	HCRYPTPROV hCryptProv; 
	HCRYPTKEY hKey; 


	PBYTE pbBuffer; 
	DWORD dwBlockLen; 
	DWORD dwBufferLen; 
	DWORD dwCount; 
 
	//-------------------------------------------------------------------
	// ��ԭ���ļ�. 
	if(hSource = fopen(szSource,"rb"))
	{
	   printf("ԭ���ļ� %s �Ѿ���. \n", szSource);
	}
	else
	{ 
	   HandleError("��ԭ���ļ�����!");
	} 

	//-------------------------------------------------------------------
	// ��Ŀ���ļ�. 
	if(hDestination = fopen(szDestination,"wb"))
	{
		 printf("Ŀ���ļ� %s �Ѿ���. \n", szDestination);
	}
	else
	{
		HandleError("��Ŀ���ļ�����!"); 
	}
	//��ȡ���ܷ����߾��
	hCryptProv = GetCryptProv();

	//-------------------------------------------------------------------
	// �����Ự��Կ.
	if(!szPassword || strcmp(szPassword,"")==0 ) 
	{ 
     
		 //--------------------------------------------------------------
		 // ����������Ϊ��ʱ���򴴽�����ļ�����Կ����������������Կ���浽�ļ���. 

		hKey = GenKeyByRandom( hCryptProv, hDestination);

		 
	} 
	else 
	{ 
		 //--------------------------------------------------------------
		 // ���������벻Ϊ��ʱ����ͨ���������봴��������Կ

		hKey=GenKeyByPassword( hCryptProv, szPassword);
		
	} 
 
	//--------------------------------------------------------------------
	// ��Ϊ�����㷨��ENCRYPT_BLOCK_SIZE ��С����ܣ����Ա����ܵ�
	// ���ݳ��ȱ�����ENCRYPT_BLOCK_SIZE �����������������һ�μ��ܵ�
	// ���ݳ��ȡ�

	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE; 

	//--------------------------------------------------------------------
	// ȷ�����ܺ��������ݿ��С. ���Ƿ�������ģʽ������������ɶ����Ŀռ�	

	if(ENCRYPT_BLOCK_SIZE > 1) 
		dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE; 
	else 
		dwBufferLen = dwBlockLen; 
    
	//-------------------------------------------------------------------
	// �����ڴ�ռ�. 
	if(pbBuffer = (BYTE *)malloc(dwBufferLen))
	{
		printf("�Ѿ�Ϊ�������������ڴ�. \n");
	}
	else
	{ 
		HandleError("�����ڴ治��. \n"); 
	}

	//-------------------------------------------------------------------
	// ѭ������ ԭ�ļ�
	do 
	{ 

		//-------------------------------------------------------------------
		// ÿ�δ�ԭ�ļ��ж�ȡdwBlockLen�ֽ�����. 
		dwCount = fread(pbBuffer, 1, dwBlockLen, hSource); 
		if(ferror(hSource))
		{ 
			HandleError("��ȡ�����ļ�����!\n");
		}
 
		//-------------------------------------------------------------------
		// ��������. 
		if(!CryptEncrypt(
			hKey,			//��Կ
			0,				//�������ͬʱ����ɢ�кͼ��ܣ����ﴫ��һ��ɢ�ж���
			feof(hSource),	//��������һ�������ܵĿ飬����TRUE.�����������FALSE.
							//����ͨ���ж��Ƿ��ļ�β�������Ƿ�Ϊ���һ�顣
			0,				//����
			pbBuffer,		//���뱻�������ݣ�������ܺ������
			&dwCount,		//���뱻��������ʵ�ʳ��ȣ�������ܺ����ݳ���
			dwBufferLen))	//pbBuffer�Ĵ�С��
		{ 
		   HandleError("Error during CryptEncrypt. \n"); 
		} 

		//-------------------------------------------------------------------
		// �Ѽ��ܺ�����д�������ļ��� 

		fwrite(pbBuffer, 1, dwCount, hDestination); 
		if(ferror(hDestination))
		{ 
			HandleError("д������ʱ����.");
		}

	} 	while(!feof(hSource)); 

	//-------------------------------------------------------------------
	// �ر��ļ�

	if(hSource)
	{
		if(fclose(hSource))
			HandleError("�ر�ԭ���ļ�����!");
	}
	if(hDestination)
	{
		if(fclose(hDestination))
			HandleError("�ر�Ŀ���ļ�����!");
	}

	//-------------------------------------------------------------------
	// �ͷ��ڴ�ռ�. 

	if(pbBuffer) 
		 free(pbBuffer); 
 
	//-------------------------------------------------------------------
	// ���ٻỰ��Կ

	if(hKey)
	{
		if(!(CryptDestroyKey(hKey)))
			HandleError("Error during CryptDestroyKey");
	}

	//-------------------------------------------------------------------
	// �ͷ�CSP���

	if(hCryptProv)
	{
		if(!(CryptReleaseContext(hCryptProv, 0)))
			HandleError("Error during CryptReleaseContext");
	}
	return(TRUE); 
} // end Encryptfile


//��ȡ�����ṩ�߾��
HCRYPTPROV GetCryptProv()
{
	HCRYPTPROV hCryptProv;                      // ���ܷ����ṩ�߾��
	
	//��ȡ�����ṩ�߾��
	if(CryptAcquireContext(
				&hCryptProv,         // ���ܷ����ṩ�߾��
				NULL,                // ��Կ������,����ʹ�õ�½�û���
				MS_ENHANCED_PROV,         // ���ܷ����ṩ��     
				PROV_RSA_FULL,       // ���ܷ����ṩ������,�����ṩ���ܺ�ǩ���ȹ���
				0))                  // ��־
	{
		printf("���ܷ����ṩ�߾����ȡ�ɹ�!\n");
	}
	else
	{
		
  
		//���½���һ���µ���Կ��
	    if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
		{
		   HandleError("���½���һ���µ���Կ������!");
		}
 
	}
	return hCryptProv;
}


//  HandleError��������������ӡ������Ϣ�����˳�����
void HandleError(char *s)
{
    printf("����ִ�з�������!\n");
    printf("%s\n",s);
    printf("�������Ϊ: %x.\n",GetLastError());
    printf("������ִֹ��!\n");
    exit(1);
}


// GenKeyByRandom��ͨ������������Ự��Կ
// ������hCryptProv CSP���
//       hDestination Ŀ���ļ��������ĻỰ��Կ�����ڴ��ļ���
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
		  printf("һ���Ự��Կ�Ѿ�������. \n");
	  } 
	  else
	  {
		  HandleError("Error during CryptGenKey. \n"); 
	  }
	 //--------------------------------------------------------------
	   // ����������Կ
	   if(CryptGenKey(
		   hCryptProv,
		   AT_KEYEXCHANGE,
		   0,
		   &hXchgKey)) 
	   {
		   printf("������Կ���Ѿ�����.\n");
	   }
	   else
	   {
		  HandleError("����ͼ����������Կʱ����.\n");
	   }

	 //--------------------------------------------------------------
	 // ȷ����Կ���ݿ鳤�ȣ�������ռ�. 

	 if(CryptExportKey(
		   hKey, 
		   hXchgKey, 
		   SIMPLEBLOB, 
		   0, 
		   NULL, 
		   &dwKeyBlobLen))
	 {
		   printf("����Կ��ĳ����� %d �ֽ�. \n",dwKeyBlobLen);
	   }
	   else
	   {  
			HandleError("������Կ���ݿ鳤�ȳ���! \n");
	   }
	   if(pbKeyBlob =(BYTE *)malloc(dwKeyBlobLen))
	   { 
		  printf("�Ѿ��ʴ���Կ��������ڴ�. \n");
	   }
	   else
	   { 
		  HandleError("�����ڴ治��. \n"); 
	   }
	 //--------------------------------------------------------------
	 // �����Ự��Կ������Կ���ݿ���. 
 
	 if(CryptExportKey(
		  hKey, 
		  hXchgKey, 
		  SIMPLEBLOB, 
		  0, 
		  pbKeyBlob, 
		  &dwKeyBlobLen))
	   {
		   printf("�˻Ự��Կ�Ѿ�������. \n");
	   } 
	   else
	   {
		   HandleError("Error during CryptExportKey!\n");
	   } 
	 //--------------------------------------------------------------
	 //�ͷŽ�����Կ���. 

	 if(hXchgKey)
	 {
		  if(!(CryptDestroyKey(hXchgKey)))
			   HandleError("Error during CryptDestroyKey"); 

		  hXchgKey = 0;
	 }

	 //--------------------------------------------------------------
	 // д��Կ�鳤�ȵ�Ŀ���ļ�. 

	 fwrite(&dwKeyBlobLen, sizeof(DWORD), 1, hDestination); 
	 if(ferror(hDestination))
	 { 
		 HandleError("д��Կ�鳤�ȳ���.");
	 }
	 else
	 {
		 printf("��Կ�鳤���Ѿ���д��. \n");
	 }
	 //--------------------------------------------------------------
	 //д��Կ�����ݵ�Ŀ���ļ�. 
 
	 fwrite(pbKeyBlob, 1, dwKeyBlobLen, hDestination); 
	 if(ferror(hDestination))
	 { 
		HandleError("д��Կ���ݳ���");
	 }
	 else
	 {
		printf("����Կ�������Ѿ���д��Ŀ���ļ�. \n");
	 }
	 // �ͷ��ڴ�ռ�.
	 free(pbKeyBlob);
	 //���ش����ĻỰ��Կ
	 return hKey;
}

// GenKeyByRandom��ͨ���������봴���Ự��Կ
// ������hCryptProv CSP���
//       szPassword ��������
HCRYPTKEY GenKeyByPassword(HCRYPTPROV hCryptProv,PCHAR szPassword)
{
	HCRYPTKEY hKey; 
	HCRYPTHASH hHash;
	//-------------------------------------------------------------------
	// ������ϣ���. 

	if(CryptCreateHash(
		   hCryptProv, 
		   CALG_MD5, 
		   0, 
		   0, 
		   &hHash))
		{
			printf("һ����ϣ����Ѿ�������. \n");
		}
		else
		{ 
			 HandleError("Error during CryptCreateHash!\n");
		}  
	//-------------------------------------------------------------------
	// ������������Ĺ�ϣֵ. 

	if(CryptHashData(
		   hHash, 
		   (BYTE *)szPassword, 
		   strlen(szPassword), 
		   0))
	 {
		printf("�����Ѿ�����ӵ��˹�ϣ����. \n");
	 }
	 else
	 {
		HandleError("Error during CryptHashData. \n"); 
	 }
	//-------------------------------------------------------------------
	// ͨ����ϣֵ�����Ự��Կ. 

	if(CryptDeriveKey(
		   hCryptProv, 
		   ENCRYPT_ALGORITHM, 
		   hHash, 
		   KEYLENGTH, 
		   &hKey))
	 {
	   printf("ͨ������Ĺ�ϣֵ����˼�����Կ. \n"); 
	 }
	 else
	 {
	   HandleError("Error during CryptDeriveKey!\n"); 
	 }
	//-------------------------------------------------------------------
	// ���ٹ�ϣ���. 

	if(hHash) 
	{
		if(!(CryptDestroyHash(hHash)))
		   HandleError("Error during CryptDestroyHash"); 
		hHash = 0;
	}

	//���ش����ĻỰ��Կ
	return hKey;
}
