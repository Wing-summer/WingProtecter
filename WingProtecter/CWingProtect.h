//
// GNU AFFERO GENERAL PUBLIC LICENSE
//Version 3, 19 November 2007
//
//Copyright(C) 2007 Free Software Foundation, Inc.
//Everyone is permitted to copyand distribute verbatim copies
//of this license document, but changing it is not allowed.
// Author : WingSummer （寂静的羽夏）
// 
//Warning : You can not use it for any commerical use,except you get 
// my AUTHORIZED FORM ME！This project is used for tutorial to teach
// the beginners what is the PE structure and how the packer of the PE files works.
// 
// 注意：你不能将该项目用于任何商业用途，除非你获得了我的授权！该项目用来
// 教初学者什么是 PE 结构和 PE 文件加壳程序是如何工作的。
// 
// Statement : It cost me about one week to write all these nearly 2500 lines of code. 
// The Assembly Engine of this project is asmjit , which is a Amazing and Fantastic toolkit 
// for generating assembly code, of course it has more powerful functions.Please keep these 
// statements  and declarations.Thanks!
// 
// 声明：该项目的代码编写用了我将近一个周的时间来写差不多2500行代码，使用的汇编引擎是 asmjit ，
// 它是一个能够生成汇编代码的强大而惊人的工具，当然它还有更多的功能。请保留这些声明，万分感谢。
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
		/// 表示不使用任何加密措施，保留
		/// </summary>
		None,
		/// <summary>
		/// 异或加密
		/// </summary>
		XOREncrypt = 1,
		/// <summary>
		/// IAT 加密
		/// </summary>
		IATEncrypt = 2,
		/// <summary>
		/// TLS 加密
		/// </summary>
		TLSEncrypt = 4,
		/// <summary>
		/// 使用花指令
		/// </summary>
		FakeCodeProtect = 8,
		/// <summary>
		/// 使用压缩壳
		/// </summary>
		Compress = 16,
		/// <summary>
		/// 反调试
		/// </summary>
		AnitDebug = 32,
		/// <summary>
		/// 使用全部保护
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
		/// 导入 Dll 的名称 RVA
		/// </summary>
		DWORD Name = 0;

		/// <summary>
		/// 总个数
		/// </summary>
		UINT FunCount = 0;
	};

	/// <summary>
	/// 加密暂存信息，所有的都是 RVA，相对于 WingSection
	/// </summary>
	struct EncryptInfo
	{
		/// <summary>
		/// 原来的导入表地址 , RVA
		/// </summary>
		UINT OldImportDataAddr = 0;

		/// <summary>
		/// 新的 IAT 地址表，它是一个数组，自定义
		/// </summary>
		UINT NewIATAddr = 0;

		/// <summary>
		/// 每个 Dll 的 FirstThunk 的 RVA，进行基址修复
		/// </summary>
		UINT FirstThunks = 0;

		/// <summary>
		/// 每个 Dll 对应的导入函数个数表，这对于填写地址十分有用 
		/// </summary>
		UINT DllFunctionsCount = 0;

		/// <summary>
		/// 导入 Dll 名称表，是一个连续的以 0 分隔开的字符串序列
		/// </summary>
		UINT ImportDllNames = 0;

		/// <summary>
		/// 导入名称表，以序号导入的不受 IAT 保护
		/// </summary>
		UINT ImportFuctionNameTable = 0;

		/// <summary>
		/// 修复实现 IAT 的汇编代码 RVA
		/// </summary>
		UINT IATShellCode = 0;

		/// <summary>
		/// 派发 IAT 的汇编代码 RVA
		/// </summary>
		UINT IATDisaptchCode = 0;

		/// <summary>
		/// 压缩数据 RVA
		/// </summary>
		UINT CompressedData = 0;

		/// <summary>
		/// 异或解密 ShellCode
		/// </summary>
		UINT XORDecodeShellCode = 0;

		/// <summary>
		/// 进行解压缩的汇编代码 RVA
		/// </summary>
		UINT ShellCodeDeCompress = 0;

		/// <summary>
		/// 启用 ShellCode 的 代码
		/// </summary>
		UINT ShellCodeLoader;

		/// <summary>
		/// TLS 缓存，用来存放 TLS 函数地址
		/// </summary>
		UINT TLSBufferShadow;

		/// <summary>
		/// TLS 缓存，用来存放执行 TLS 函数地址
		/// </summary>
		UINT TLSBuffer;

		/// <summary>
		/// TLS 派发函数
		/// </summary>
		UINT TLSDispatcher;

		/// <summary>
		/// 原来的 TLS CallBack RVA	
		/// </summary>
		UINT OldTLSCallBacks = 0;
	};

	struct Analysis
	{
		/// <summary>
		/// 给新建节区最小的 RVA
		/// </summary>
		UINT MinAvailableVirtualAddress = 0;
		/// <summary>
		/// 可以在不扩大节的情况下，可再次添加的节区
		/// </summary>
		UINT SectionsCanAddCount = 0;

		/// <summary>
		/// 导入表 Dll 名称
		/// </summary>
		DllImportName* ImportDllName = nullptr;

		/// <summary>
		/// ImportDllName 实际个数
		/// </summary>
		UINT ImportDllCount = 0;

		/// <summary>
		/// 导入表函数名称表
		/// </summary>
		char* ImportFunNameTable = nullptr;

		/// <summary>
		/// 使用导入表函数名称表的指针，数值上等于使用的数量
		/// </summary>
		UINT PointerofImportFunNameTable = 0;

		/// <summary>
		/// 每个 Dll 导入表的首地址
		/// </summary>
		UINT* DllFirstThunks = nullptr;

		/// <summary>
		/// 导入表函数总数个数
		/// </summary>
		UINT ImportFunCount = 0;
	};

	struct PEInfo
	{
		/// <summary>
		/// 原文件大小
		/// </summary>
		LARGE_INTEGER FileSize = { 0,0 };

		/// <summary>
		/// NT 头在文件中的偏移
		/// </summary>
		UINT ntHeaderOffset = 0;

		/// <summary>
		/// 节的数量
		/// </summary>
		UINT NumberOfSections = 0;

		/// <summary>
		/// 希望加载的地址
		/// </summary>
		INT3264 ImageBase = 0;

		/// <summary>
		///  NumberOfSections 地址
		/// </summary>
		INT3264 PNumberOfSections = 0;

		/// <summary>
		/// 可执行入口地址
		/// </summary>
		UINT AddressOfEntryPoint = 0;

		/// <summary>
		/// AddressOfEntryPoint 地址
		/// </summary>
		INT3264 PAddressOfEntryPoint = 0;

		/// <summary>
		/// 子系统
		/// </summary>
		UINT Subsystem = 0;

		/// <summary>
		/// 文件对齐
		/// </summary>
		UINT FileAlignment = 0;

		/// <summary>
		/// 内存对齐
		/// </summary>
		UINT SectionAlignment = 0;

		/// <summary>
		/// 内存中整个PE文件的映射的尺寸，必须是SectionAlignment的整数倍
		/// </summary>
		UINT SizeOfImage = 0;

		/// <summary>
		/// SizeOfImage 地址
		/// </summary>
		INT3264 PSizeOfImage = 0;

		/// <summary>
		/// 所有头和节表按照文件对齐后的大小
		/// </summary>
		UINT SizeOfHeaders = 0;

		/// <summary>
		/// SizeOfHeaders 地址
		/// </summary>
		INT3264 PSizeOfHeaders = 0;

		/// <summary>
		/// SectionHeaders 地址
		/// </summary>
		PIMAGE_SECTION_HEADER PSectionHeaders = nullptr;

		/// <summary>
		/// DataDirectory 地址
		/// </summary>
		PIMAGE_DATA_DIRECTORY PDataDirectory = nullptr;

		/// <summary>
		/// 导入表地址
		/// </summary>
		PIMAGE_IMPORT_DESCRIPTOR PImportDescriptor = nullptr;

		/// <summary>
		/// 代码节区，加壳重点区域
		/// </summary>
		PIMAGE_SECTION_HEADER PCodeSection = nullptr;

		/// <summary>
		/// 导入表节区，修改属性时需要
		/// </summary>
		PIMAGE_SECTION_HEADER PImportSection = nullptr;

		/// <summary>
		/// OptionalHeader.DllCharacteristics 地址
		/// </summary>
		WORD* POptionalHeaderDllCharacteristics = nullptr;

		/// <summary>
		/// OptionalHeader.DllCharacteristics
		/// </summary>
		WORD OptionalHeaderDllCharacteristics = 0;

		/// <summary>
		/// 分析 PE 信息
		/// </summary>
		Analysis AnalysisInfo{};

		/// <summary>
		/// WingSection 段，最大为 40 KB
		/// </summary>
		LPVOID WingSecitonBuffer = nullptr;

		/// <summary>
		/// 指示已经使用的 WingSeciton 大小，非对齐值
		/// </summary>
		INT3264 PointerOfWingSeciton = 0;

		/// <summary>
		/// WingSection 描述信息
		/// </summary>
		PIMAGE_SECTION_HEADER WingSection = nullptr;
	};

	class CWingProtect
	{
	public:
		CWingProtect(const TCHAR* filename, UINT pagecount = 10);
		~CWingProtect();

		/// <summary>
		/// 分配一个页大小的内存
		/// </summary>
		/// <returns></returns>
		LPVOID AllocPageSizeMemory();

		/// <summary>
		/// 获取最后一个错误号
		/// </summary>
		/// <returns></returns>
		ParserError GetLastErr();

		/// <summary>
		/// 
		/// </summary>
		/// <returns></returns>
		BOOL IsSuccess();

		/// <summary>
		/// 获取此 PE 文件是否可以支持 IAT 加密
		/// </summary>
		/// <returns></returns>
		BOOL IsEnableIATEncrypt();

		/// <summary>
		/// 启用保护
		/// </summary>
		BOOL Proctect(UINT protection);

		/// <summary>
		/// 保存到文件，如果该函数返回失败，请调用 GetLastError() 获取错误码
		/// </summary>
		/// <param name="filename"></param>
		/// <returns></returns>
		BOOL Save2File(const TCHAR* filename);
	private:

		/// <summary>
		/// 摧毁重定位表
		/// </summary>
		void DestoryRelocation();

		/// <summary>
		/// 生成引导 ShellCode
		/// </summary>
		/// <param name="protections">保护</param>
		/// <param name="FakeCode"></param>
		void GenerateLoadingShellCode(UINT protections, BOOL FakeCode);

		/// <summary>
		/// 判断是否使用某些保护
		/// </summary>
		/// <param name="protections"></param>
		/// <param name="flag"></param>
		/// <returns></returns>
		BOOL ProtectionsHasFlag(UINT protections, Protections flag);

		/// <summary>
		/// 初步解析 PE 文件
		/// </summary>
		/// <returns></returns>
		ParserError ParsePE();

		/// <summary>
		/// 解析 32 位的 PE 文件
		/// </summary>
		/// <param name="ntHeader"></param>
		/// <returns></returns>
		ParserError Parse32(PIMAGE_NT_HEADERS ntHeader);

		/// <summary>
		/// 解析 64 位的 PE 文件
		/// </summary>
		/// <param name="ntHeader"></param>
		/// <returns></returns>
		ParserError Parse64(PIMAGE_NT_HEADERS ntHeader);

		/// <summary>
		/// 解析 PE 目录表
		/// </summary>
		/// <param name="ntHeader"></param>
		/// <returns></returns>
		ParserError ParserDir(PIMAGE_NT_HEADERS ntHeader);

		/// <summary>
		/// 给 PE 加 XOR 异或加密壳
		/// </summary>
		/// <param name="NeedReloc">是否处理重定位</param>
		/// <param name="FakeCode"></param>
		/// <returns></returns>
		BOOL XORCodeSection(BOOL NeedReloc, BOOL FakeCode);

		/// <summary>
		/// 使用最简单的 RLE 压缩算法压缩
		/// </summary>
		/// <param name="NeedReloc">是否处理重定位</param>
		/// <param name="FakeCode"></param>
		/// <returns></returns>
		BOOL CompressSeciton(BOOL NeedReloc, BOOL FakeCode);

		/// <summary>
		/// IAT 表加密
		/// </summary>
		/// <param name="AntiDebug"></param>
		/// <param name="FakeCode"></param>
		/// <returns></returns>
		BOOL IATEncrypt(BOOL AntiDebug, BOOL FakeCode);

		/// <summary>
		/// 生成重定位汇编代码
		/// </summary>
		/// <param name="a"></param>
		void RelocationSection(asmjit::x86::Assembler& a);

		/// <summary>
		/// 将非编辑区地址转为编辑区地址
		/// </summary>
		/// <param name="Addr">非编辑区地址</param>
		/// <returns></returns>
		inline INT3264 TranModPE(INT3264 Addr);

		/// <summary>
		/// 修正 WingSection 的信息
		/// </summary>
		void CorrectWingSection();

		/// <summary>
		/// 处理 TLS
		/// </summary>
		/// <param name="Encrypt">是否进行加密</param>
		/// <returns></returns>
		BOOL ProcessTLS(BOOL Encrypt);

		/// <summary>
		/// RVA 转为 FOA
		/// </summary>
		/// <param name="rva"></param>
		/// <returns></returns>
		INT3264 RVA2FOA(INT3264 rva);

		/// <summary>
		/// FOA 转为 RVA
		/// </summary>
		/// <param name="ofa"></param>
		/// <returns></returns>
		INT3264 FOA2RVA(INT3264 foa);

	private:
		/// <summary>
		/// 要加密的 PE 文件的文件名缓存
		/// </summary>
		TCHAR _filename[MAX_PATH + 1] = { 0 };

		/// <summary>
		/// 最后一个解析状态
		/// </summary>
		ParserError _lasterror = ParserError::UnLoadedFile;

		/// <summary>
		/// PE 是否是64位的
		/// </summary>
		BOOL is64bit = FALSE;

		/// <summary>
		/// 标识是否需要修复导入表大小
		/// </summary>
		BOOL ImportTableNeedCorrent = FALSE;

		/// <summary>
		/// PE 原文件读取缓存
		/// </summary>
		LPVOID mapping = NULL;

		/// <summary>
		/// PE 原文件句柄
		/// </summary>
		HANDLE hfile;

		/// <summary>
		/// PE mapping 句柄
		/// </summary>
		HANDLE hmap;

		/// <summary>
		/// PE 修改缓存
		/// </summary>
		LPVOID packedPE = NULL;

		/// <summary>
		/// 是否支持 IAT 加密
		/// </summary>
		BOOL EnableIATEncrypt = TRUE;

		/// <summary>
		/// 指示 PE 文件是否含有 TLS
		/// </summary>
		BOOL HasTLS = FALSE;

		/// <summary>
		/// 与 PE 解析相关的信息
		/// </summary>
		PEInfo peinfo;

		/// <summary>
		/// 加密处理必须暂存的信息
		/// </summary>
		EncryptInfo encryptInfo;
	};

}


