//
// GNU AFFERO GENERAL PUBLIC LICENSE
//Version 3, 19 November 2007
//
//Copyright(C) 2007 Free Software Foundation, Inc.
//Everyone is permitted to copyand distribute verbatim copies
//of this license document, but changing it is not allowed.
// Author : WingSummer ���ž������ģ�
// 
//Warning : You can not use it for any commerical use,except you get 
// my AUTHORIZED FORM ME��This project is used for tutorial to teach
// the beginners what is the PE structure and how the packer of the PE files works.
// 
// ע�⣺�㲻�ܽ�����Ŀ�����κ���ҵ��;�������������ҵ���Ȩ������Ŀ����
// �̳�ѧ��ʲô�� PE �ṹ�� PE �ļ��ӿǳ�������ι����ġ�
// 
// Statement : It cost me about one week to write all these nearly 2500 lines of code. 
// The Assembly Engine of this project is asmjit , which is a Amazing and Fantastic toolkit 
// for generating assembly code, of course it has more powerful functions.Please keep these 
// statements  and declarations.Thanks!
// 
// ����������Ŀ�Ĵ����д�����ҽ���һ���ܵ�ʱ����д���2500�д��룬ʹ�õĻ�������� asmjit ��
// ����һ���ܹ����ɻ������ǿ������˵Ĺ��ߣ���Ȼ�����и���Ĺ��ܡ��뱣����Щ��������ָ�л��
//


#pragma once
#include <iostream>
#include <list>
#include<Windows.h>
using namespace std;

#define INT3264 __int3264

#include "asmjit/asmjit.h"
#pragma comment(lib,"shlwapi.lib")

#ifdef _DEBUG
#pragma comment(lib,"asmjit_d.lib")
#else
#pragma comment(lib,"asmjit.lib")
#endif 

#define WingProtectFakeCode "\xEB\xCWingProtect\xEB"
#define SizeofWingProtectFakeCode (sizeof(WingProtectFakeCode)-1)
#define FakeProtect(a) a.embed(WingProtectFakeCode, SizeofWingProtectFakeCode);

namespace WingProtect
{

	enum Protections
	{
		/// <summary>
		/// ��ʾ��ʹ���κμ��ܴ�ʩ������
		/// </summary>
		None,
		/// <summary>
		/// ������
		/// </summary>
		XOREncrypt = 1,
		/// <summary>
		/// IAT ����
		/// </summary>
		IATEncrypt = 2,
		/// <summary>
		/// TLS ����
		/// </summary>
		TLSEncrypt = 4,
		/// <summary>
		/// ʹ�û�ָ��
		/// </summary>
		FakeCodeProtect = 8,
		/// <summary>
		/// ʹ��ѹ����
		/// </summary>
		Compress = 16,
		/// <summary>
		/// ������
		/// </summary>
		AnitDebug = 32,
		/// <summary>
		/// ʹ��ȫ������
		/// </summary>
		AllProtect = XOREncrypt | IATEncrypt | TLSEncrypt | FakeCodeProtect | Compress
	};

	enum class ParserError
	{
		UnLoadedFile,
		LoadingFile,
		Success,
		FileNotFound,
		InvalidFile,
		InvalidFileName,
		OpenFileError,
		FileMappingError,
		MapViewOfFileError,
		InvalidPE,
		DriverUnsupport,
		CannotAllocMemory,
		TooManyImportDlls,
		TooManyImportFunctions
	};

	struct DllImportName
	{
		/// <summary>
		/// ���� Dll ������ RVA
		/// </summary>
		DWORD Name = 0;

		/// <summary>
		/// �ܸ���
		/// </summary>
		UINT FunCount = 0;
	};

	/// <summary>
	/// �����ݴ���Ϣ�����еĶ��� RVA������� WingSection
	/// </summary>
	struct EncryptInfo
	{
		/// <summary>
		/// ԭ���ĵ�����ַ , RVA
		/// </summary>
		UINT OldImportDataAddr = 0;

		/// <summary>
		/// �µ� IAT ��ַ������һ�����飬�Զ���
		/// </summary>
		UINT NewIATAddr = 0;

		/// <summary>
		/// ÿ�� Dll �� FirstThunk �� RVA�����л�ַ�޸�
		/// </summary>
		UINT FirstThunks = 0;

		/// <summary>
		/// ÿ�� Dll ��Ӧ�ĵ��뺯���������������д��ַʮ������ 
		/// </summary>
		UINT DllFunctionsCount = 0;

		/// <summary>
		/// ���� Dll ���Ʊ���һ���������� 0 �ָ������ַ�������
		/// </summary>
		UINT ImportDllNames = 0;

		/// <summary>
		/// �������Ʊ�����ŵ���Ĳ��� IAT ����
		/// </summary>
		UINT ImportFuctionNameTable = 0;

		/// <summary>
		/// �޸�ʵ�� IAT �Ļ����� RVA
		/// </summary>
		UINT IATShellCode = 0;

		/// <summary>
		/// �ɷ� IAT �Ļ����� RVA
		/// </summary>
		UINT IATDisaptchCode = 0;

		/// <summary>
		/// ѹ������ RVA
		/// </summary>
		UINT CompressedData = 0;

		/// <summary>
		/// ������ ShellCode
		/// </summary>
		UINT XORDecodeShellCode = 0;

		/// <summary>
		/// ���н�ѹ���Ļ����� RVA
		/// </summary>
		UINT ShellCodeDeCompress = 0;

		/// <summary>
		/// ���� ShellCode �� ����
		/// </summary>
		UINT ShellCodeLoader;

		/// <summary>
		/// TLS ���棬������� TLS ������ַ
		/// </summary>
		UINT TLSBufferShadow;

		/// <summary>
		/// TLS ���棬�������ִ�� TLS ������ַ
		/// </summary>
		UINT TLSBuffer;

		/// <summary>
		/// TLS �ɷ�����
		/// </summary>
		UINT TLSDispatcher;

		/// <summary>
		/// ԭ���� TLS CallBack RVA	
		/// </summary>
		UINT OldTLSCallBacks = 0;
	};

	struct Analysis
	{
		/// <summary>
		/// ���½�������С�� RVA
		/// </summary>
		UINT MinAvailableVirtualAddress = 0;
		/// <summary>
		/// �����ڲ�����ڵ�����£����ٴ���ӵĽ���
		/// </summary>
		UINT SectionsCanAddCount = 0;

		/// <summary>
		/// ����� Dll ����
		/// </summary>
		DllImportName* ImportDllName = nullptr;

		/// <summary>
		/// ImportDllName ʵ�ʸ���
		/// </summary>
		UINT ImportDllCount = 0;

		/// <summary>
		/// ����������Ʊ�
		/// </summary>
		char* ImportFunNameTable = nullptr;

		/// <summary>
		/// ʹ�õ���������Ʊ��ָ�룬��ֵ�ϵ���ʹ�õ�����
		/// </summary>
		UINT PointerofImportFunNameTable = 0;

		/// <summary>
		/// ÿ�� Dll �������׵�ַ
		/// </summary>
		UINT* DllFirstThunks = nullptr;

		/// <summary>
		/// ���������������
		/// </summary>
		UINT ImportFunCount = 0;
	};

	struct PEInfo
	{
		/// <summary>
		/// ԭ�ļ���С
		/// </summary>
		LARGE_INTEGER FileSize = { 0,0 };

		/// <summary>
		/// NT ͷ���ļ��е�ƫ��
		/// </summary>
		UINT ntHeaderOffset = 0;

		/// <summary>
		/// �ڵ�����
		/// </summary>
		UINT NumberOfSections = 0;

		/// <summary>
		/// ϣ�����صĵ�ַ
		/// </summary>
		INT3264 ImageBase = 0;

		/// <summary>
		///  NumberOfSections ��ַ
		/// </summary>
		INT3264 PNumberOfSections = 0;

		/// <summary>
		/// ��ִ����ڵ�ַ
		/// </summary>
		UINT AddressOfEntryPoint = 0;

		/// <summary>
		/// AddressOfEntryPoint ��ַ
		/// </summary>
		INT3264 PAddressOfEntryPoint = 0;

		/// <summary>
		/// ��ϵͳ
		/// </summary>
		UINT Subsystem = 0;

		/// <summary>
		/// �ļ�����
		/// </summary>
		UINT FileAlignment = 0;

		/// <summary>
		/// �ڴ����
		/// </summary>
		UINT SectionAlignment = 0;

		/// <summary>
		/// �ڴ�������PE�ļ���ӳ��ĳߴ磬������SectionAlignment��������
		/// </summary>
		UINT SizeOfImage = 0;

		/// <summary>
		/// SizeOfImage ��ַ
		/// </summary>
		INT3264 PSizeOfImage = 0;

		/// <summary>
		/// ����ͷ�ͽڱ����ļ������Ĵ�С
		/// </summary>
		UINT SizeOfHeaders = 0;

		/// <summary>
		/// SizeOfHeaders ��ַ
		/// </summary>
		INT3264 PSizeOfHeaders = 0;

		/// <summary>
		/// SectionHeaders ��ַ
		/// </summary>
		PIMAGE_SECTION_HEADER PSectionHeaders = nullptr;

		/// <summary>
		/// DataDirectory ��ַ
		/// </summary>
		PIMAGE_DATA_DIRECTORY PDataDirectory = nullptr;

		/// <summary>
		/// ������ַ
		/// </summary>
		PIMAGE_IMPORT_DESCRIPTOR PImportDescriptor = nullptr;

		/// <summary>
		/// ����������ӿ��ص�����
		/// </summary>
		PIMAGE_SECTION_HEADER PCodeSection = nullptr;

		/// <summary>
		/// �����������޸�����ʱ��Ҫ
		/// </summary>
		PIMAGE_SECTION_HEADER PImportSection = nullptr;

		/// <summary>
		/// OptionalHeader.DllCharacteristics ��ַ
		/// </summary>
		WORD* POptionalHeaderDllCharacteristics = nullptr;

		/// <summary>
		/// OptionalHeader.DllCharacteristics
		/// </summary>
		WORD OptionalHeaderDllCharacteristics = 0;

		/// <summary>
		/// ���� PE ��Ϣ
		/// </summary>
		Analysis AnalysisInfo{};

		/// <summary>
		/// WingSection �Σ����Ϊ 40 KB
		/// </summary>
		LPVOID WingSecitonBuffer = nullptr;

		/// <summary>
		/// ָʾ�Ѿ�ʹ�õ� WingSeciton ��С���Ƕ���ֵ
		/// </summary>
		INT3264 PointerOfWingSeciton = 0;

		/// <summary>
		/// WingSection ������Ϣ
		/// </summary>
		PIMAGE_SECTION_HEADER WingSection = nullptr;
	};

	class CWingProtect
	{
	public:
		CWingProtect(const TCHAR* filename, UINT pagecount = 10);
		~CWingProtect();

		/// <summary>
		/// ����һ��ҳ��С���ڴ�
		/// </summary>
		/// <returns></returns>
		LPVOID AllocPageSizeMemory();

		/// <summary>
		/// ��ȡ���һ�������
		/// </summary>
		/// <returns></returns>
		ParserError GetLastErr();

		/// <summary>
		/// 
		/// </summary>
		/// <returns></returns>
		BOOL IsSuccess();

		/// <summary>
		/// ��ȡ�� PE �ļ��Ƿ����֧�� IAT ����
		/// </summary>
		/// <returns></returns>
		BOOL IsEnableIATEncrypt();

		/// <summary>
		/// ���ñ���
		/// </summary>
		BOOL Proctect(UINT protection);

		/// <summary>
		/// ���浽�ļ�������ú�������ʧ�ܣ������ GetLastError() ��ȡ������
		/// </summary>
		/// <param name="filename"></param>
		/// <returns></returns>
		BOOL Save2File(const TCHAR* filename);
	private:

		/// <summary>
		/// �ݻ��ض�λ��
		/// </summary>
		void DestoryRelocation();

		/// <summary>
		/// �������� ShellCode
		/// </summary>
		/// <param name="protections">����</param>
		/// <param name="FakeCode"></param>
		void GenerateLoadingShellCode(UINT protections, BOOL FakeCode);

		/// <summary>
		/// �ж��Ƿ�ʹ��ĳЩ����
		/// </summary>
		/// <param name="protections"></param>
		/// <param name="flag"></param>
		/// <returns></returns>
		BOOL ProtectionsHasFlag(UINT protections, Protections flag);

		/// <summary>
		/// �������� PE �ļ�
		/// </summary>
		/// <returns></returns>
		ParserError ParsePE();

		/// <summary>
		/// ���� 32 λ�� PE �ļ�
		/// </summary>
		/// <param name="ntHeader"></param>
		/// <returns></returns>
		ParserError Parse32(PIMAGE_NT_HEADERS ntHeader);

		/// <summary>
		/// ���� 64 λ�� PE �ļ�
		/// </summary>
		/// <param name="ntHeader"></param>
		/// <returns></returns>
		ParserError Parse64(PIMAGE_NT_HEADERS ntHeader);

		/// <summary>
		/// ���� PE Ŀ¼��
		/// </summary>
		/// <param name="ntHeader"></param>
		/// <returns></returns>
		ParserError ParserDir(PIMAGE_NT_HEADERS ntHeader);

		/// <summary>
		/// �� PE �� XOR �����ܿ�
		/// </summary>
		/// <param name="NeedReloc">�Ƿ����ض�λ</param>
		/// <param name="FakeCode"></param>
		/// <returns></returns>
		BOOL XORCodeSection(BOOL NeedReloc, BOOL FakeCode);

		/// <summary>
		/// ʹ����򵥵� RLE ѹ���㷨ѹ��
		/// </summary>
		/// <param name="NeedReloc">�Ƿ����ض�λ</param>
		/// <param name="FakeCode"></param>
		/// <returns></returns>
		BOOL CompressSeciton(BOOL NeedReloc, BOOL FakeCode);

		/// <summary>
		/// IAT �����
		/// </summary>
		/// <param name="AntiDebug"></param>
		/// <param name="FakeCode"></param>
		/// <returns></returns>
		BOOL IATEncrypt(BOOL AntiDebug, BOOL FakeCode);

		/// <summary>
		/// �����ض�λ������
		/// </summary>
		/// <param name="a"></param>
		void RelocationSection(asmjit::x86::Assembler& a);

		/// <summary>
		/// ���Ǳ༭����ַתΪ�༭����ַ
		/// </summary>
		/// <param name="Addr">�Ǳ༭����ַ</param>
		/// <returns></returns>
		inline INT3264 TranModPE(INT3264 Addr);

		/// <summary>
		/// ���� WingSection ����Ϣ
		/// </summary>
		void CorrectWingSection();

		/// <summary>
		/// ���� TLS
		/// </summary>
		/// <param name="Encrypt">�Ƿ���м���</param>
		/// <returns></returns>
		BOOL ProcessTLS(BOOL Encrypt);

		/// <summary>
		/// RVA תΪ FOA
		/// </summary>
		/// <param name="rva"></param>
		/// <returns></returns>
		INT3264 RVA2FOA(INT3264 rva);

		/// <summary>
		/// FOA תΪ RVA
		/// </summary>
		/// <param name="ofa"></param>
		/// <returns></returns>
		INT3264 FOA2RVA(INT3264 foa);

	private:
		/// <summary>
		/// Ҫ���ܵ� PE �ļ����ļ�������
		/// </summary>
		TCHAR _filename[MAX_PATH + 1] = { 0 };

		/// <summary>
		/// ���һ������״̬
		/// </summary>
		ParserError _lasterror = ParserError::UnLoadedFile;

		/// <summary>
		/// PE �Ƿ���64λ��
		/// </summary>
		BOOL is64bit = FALSE;

		/// <summary>
		/// ��ʶ�Ƿ���Ҫ�޸�������С
		/// </summary>
		BOOL ImportTableNeedCorrent = FALSE;

		/// <summary>
		/// PE ԭ�ļ���ȡ����
		/// </summary>
		LPVOID mapping = NULL;

		/// <summary>
		/// PE ԭ�ļ����
		/// </summary>
		HANDLE hfile;

		/// <summary>
		/// PE mapping ���
		/// </summary>
		HANDLE hmap;

		/// <summary>
		/// PE �޸Ļ���
		/// </summary>
		LPVOID packedPE = NULL;

		/// <summary>
		/// �Ƿ�֧�� IAT ����
		/// </summary>
		BOOL EnableIATEncrypt = TRUE;

		/// <summary>
		/// ָʾ PE �ļ��Ƿ��� TLS
		/// </summary>
		BOOL HasTLS = FALSE;

		/// <summary>
		/// �� PE ������ص���Ϣ
		/// </summary>
		PEInfo peinfo;

		/// <summary>
		/// ���ܴ�������ݴ����Ϣ
		/// </summary>
		EncryptInfo encryptInfo;
	};

}


