//
// GNU AFFERO GENERAL PUBLIC LICENSE
//Version 3, 19 November 2007
//
//Copyright(C) 2007 Free Software Foundation, Inc.
//Everyone is permitted to copyand distribute verbatim copies
//of this license document, but changing it is not allowed.
// Author : WingSummer ���ž������ģ�
// 
//Warning: You can not use it for any commerical use,except you get 
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

#include "CWingProtect.h"

#include <shlwapi.h> 
#include <string>
#include <assert.h>
#include <vector>

#define OFFSET(Base, Offset)   ((INT3264)Base + (INT3264)Offset)
#define GetPointerByOffset(Base, Offset)   ((LPVOID)OFFSET(Base, Offset))
#define GetPointerByRVA(Base, RVAOffset)  GetPointerByOffset(Base, RVA2FOA(RVAOffset))
#define GETOFFSET(Base,End) ((INT3264)End - (INT3264)Base)
#define GetStringFormRVA(Base, RVA)  string((char *)GetPointerByRVA(Base, RVA))

#define AllocReadWriteMem(Size) VirtualAlloc(NULL, Size, MEM_COMMIT, PAGE_READWRITE)
#define FREEMEM(Mem) VirtualFree(Mem, 0, MEM_FREE);

#define GetBiggerQuot(div) (div.quot + (div.rem > 0 ? 1 : 0))
#define TranModPEWapper(Addr)  TranModPE((INT3264)Addr)

#define INVALID_ADDR -1
#define PageSize 0x1000
#define MAXDllNameCount PageSize/sizeof(DllImportName)
#define MAXImportFunHintCount PageSize/sizeof(WORD)

#define SaveEasyLostReg64(a) a.nop();a.push(x86::rcx);a.push(x86::rdx);a.push(x86::r8);a.push(x86::r9);a.push(x86::r10);a.push(x86::r11);a.nop();
#define RestoreEasyLostReg64(a) a.nop();a.pop(x86::r11);a.pop(x86::r10);a.pop(x86::r9);a.pop(x86::r8);a.pop(x86::rdx);a.pop(x86::rcx);a.nop();

#define SaveEasyLostReg32(a) a.nop();a.push(x86::ecx);a.push(x86::edx);a.nop();
#define RestoreEasyLostReg32(a) a.nop();a.pop(x86::edx);a.pop(x86::ecx);a.nop();

namespace WingProtect
{

	CWingProtect::CWingProtect(const TCHAR* filename,UINT pagecount)
	{
		//��ʼ��������Ҫ�õ����ڴ�
		auto alloc = AllocPageSizeMemory();
		if (!alloc)
		{
			_lasterror = ParserError::CannotAllocMemory;
			return;
		}
		memset(alloc, 0, PageSize);
		peinfo.AnalysisInfo.ImportDllName = (DllImportName*)alloc;

		alloc = AllocReadWriteMem(PageSize * 10);
		if (!alloc)
		{
			_lasterror = ParserError::CannotAllocMemory;
			return;
		}
		memset(alloc, 0, PageSize * 10);
		peinfo.AnalysisInfo.ImportFunNameTable = (char*)alloc;

		alloc = AllocPageSizeMemory();
		if (!alloc)
		{
			_lasterror = ParserError::CannotAllocMemory;
			return;
		}
		memset(alloc, 0, PageSize);
		peinfo.AnalysisInfo.DllFirstThunks = (UINT*)alloc;

		//�����������

		_lasterror = ParserError::LoadingFile;
		if (wcscpy_s(_filename, filename))
		{
			_lasterror = ParserError::InvalidFileName;
			return;
		}

		_lasterror = ParsePE();

		//�������Ļ������������Դ
		switch (_lasterror)
		{
		case ParserError::InvalidPE:
			UnmapViewOfFile(hmap);
			mapping = NULL;
		case ParserError::MapViewOfFileError:
			if (hmap) CloseHandle(hmap);
		case ParserError::FileMappingError:
			CloseHandle(hfile);
			::memset(&peinfo, 0, sizeof(PEInfo));
			break;
		case ParserError::OpenFileError:
			break;
		case ParserError::TooManyImportDlls:
		case ParserError::TooManyImportFunctions:
			EnableIATEncrypt = FALSE;
			break;
		default:
			break;
		}

		//������Ϻ󴴽�һ���ڸ�ֵ
		peinfo.WingSection = new IMAGE_SECTION_HEADER{};
		peinfo.WingSection->VirtualAddress = peinfo.AnalysisInfo.MinAvailableVirtualAddress;

		alloc = AllocReadWriteMem(PageSize * pagecount);
		if (!alloc)
		{
			_lasterror = ParserError::CannotAllocMemory;
			return;
		}
		memset(alloc, 0, PageSize * pagecount);
		peinfo.WingSecitonBuffer = alloc;

		auto filesize = peinfo.FileSize.QuadPart;
		alloc = AllocReadWriteMem(filesize);
		if (!alloc)
		{ 
			_lasterror = ParserError::CannotAllocMemory;
			return;
		}
		packedPE = alloc;
		memcpy_s(packedPE, filesize, mapping, filesize);

	}

	CWingProtect::~CWingProtect()
	{
		if (mapping)
		{
			UnmapViewOfFile(mapping);
			mapping = NULL;
			CloseHandle(hmap);
			CloseHandle(hfile);
		}

		FREEMEM(peinfo.AnalysisInfo.ImportDllName);
		FREEMEM(peinfo.AnalysisInfo.ImportFunNameTable);
		FREEMEM(peinfo.AnalysisInfo.DllFirstThunks);

		if (peinfo.WingSection)
		{
			FREEMEM(peinfo.WingSecitonBuffer);
			delete peinfo.WingSection;
		}
	}

	void CWingProtect::GenerateLoadingShellCode(UINT protections, BOOL FakeCode)
	{
		auto buffer = GetPointerByOffset(peinfo.WingSecitonBuffer, peinfo.PointerOfWingSeciton);

		encryptInfo.ShellCodeLoader = (UINT)peinfo.PointerOfWingSeciton;

		using namespace asmjit;
		if (is64bit)
		{
			Environment env(Arch::kX64);
			CodeHolder holder;
			holder.init(env);
			x86::Assembler a(&holder);

			x86::Mem mem;
			mem.setSegment(x86::gs);
			mem.setOffset(0x60);

			a.mov(x86::rax, mem);
			a.mov(x86::rax, x86::qword_ptr(x86::rax, 0x10));

			auto rvabase = peinfo.AnalysisInfo.MinAvailableVirtualAddress;
#define AddRVABase(offset) ((UINT)offset + (UINT)rvabase)

			if (ProtectionsHasFlag(protections,Protections::IATEncrypt))
			{
				a.push(x86::rax);
				a.add(x86::rax, AddRVABase(encryptInfo.IATShellCode));
				a.call(x86::rax);
				a.pop(x86::rax);
				a.nop();
			}

			if (ProtectionsHasFlag(protections,Protections::Compress))
			{
				a.push(x86::rax);
				a.add(x86::rax, AddRVABase(encryptInfo.ShellCodeDeCompress));
				a.call(x86::rax);
				a.pop(x86::rax);
				a.nop();
			}

			if (ProtectionsHasFlag(protections,Protections::XOREncrypt))
			{
				a.push(x86::rax);
				a.add(x86::rax, AddRVABase(encryptInfo.XORDecodeShellCode));
				a.call(x86::rax);
				a.pop(x86::rax);
				a.nop();
			}

			if (HasTLS)
			{
				Label loop = a.newLabel();
				Label loop_j = a.newLabel();
				Label addn = a.newLabel();

				a.push(x86::rax);
				a.push(x86::rdi);
				a.push(x86::rsi);
				a.push(x86::rbx);

				a.mov(x86::rsi, encryptInfo.OldTLSCallBacks);
				a.mov(x86::rdi, AddRVABase(encryptInfo.TLSBuffer));
				a.add(x86::rsi, x86::rax);
				a.add(x86::rdi, x86::rax);

				a.bind(loop);
				a.mov(x86::rbx, x86::qword_ptr(x86::rsi));
				a.test(x86::ebx, x86::ebx);
				a.jz(loop_j);

				a.cmp(x86::rbx, x86::rax);		//���û�� TLS ���������ʾ RVA ����Ҫת��Ϊ��ַ
				a.ja(addn);
				a.add(x86::rbx, x86::rax);
				a.bind(addn);

				a.mov(x86::qword_ptr(x86::rdi), x86::rbx);
				a.add(x86::rsi, 8);
				a.add(x86::rdi, 8);
				a.jmp(loop);
				a.bind(loop_j);

				a.pop(x86::rbx);
				a.pop(x86::rsi);
				a.pop(x86::rdi);
				a.pop(x86::rax);
				a.nop();
			}

			a.add(x86::rax, peinfo.AddressOfEntryPoint);
			a.jmp(x86::rax);

			BYTE* shellcode = a.bufferData();
			UINT codesize = (UINT)holder.codeSize();

			memcpy_s(buffer, codesize, shellcode, codesize);
			peinfo.PointerOfWingSeciton += codesize;
		}
		else
		{
			Environment env(Arch::kX86);
			CodeHolder holder;
			holder.init(env);
			x86::Assembler a(&holder);

			x86::Mem mem;
			mem.setSegment(x86::fs);
			mem.setOffset(0x30);

			a.mov(x86::eax, mem);
			a.mov(x86::eax, x86::qword_ptr(x86::eax, 0x10));
			a.push(x86::ebx);

			auto rvabase = peinfo.AnalysisInfo.MinAvailableVirtualAddress;
#define AddRVABase(offset) ((UINT)offset + (UINT)rvabase)

			if (ProtectionsHasFlag(protections, Protections::IATEncrypt))
			{
				a.push(x86::eax);
				a.mov(x86::ebx, AddRVABase(encryptInfo.IATShellCode));
				a.add(x86::ebx, x86::eax);
				a.call(x86::ebx);
				a.pop(x86::eax);
				a.nop();
			}

			if (ProtectionsHasFlag(protections, Protections::Compress))
			{
				a.push(x86::eax);
				a.mov(x86::ebx, AddRVABase(encryptInfo.ShellCodeDeCompress));
				a.add(x86::ebx, x86::eax);
				a.call(x86::ebx);
				a.pop(x86::eax);
				a.nop();
			}

			if (ProtectionsHasFlag(protections, Protections::XOREncrypt))
			{
				a.push(x86::eax);
				a.mov(x86::ebx, AddRVABase(encryptInfo.XORDecodeShellCode));
				a.add(x86::ebx, x86::eax);
				a.call(x86::ebx);
				a.pop(x86::eax);
				a.nop();
			}

			a.pop(x86::ebx);
			a.add(x86::eax, peinfo.AddressOfEntryPoint);
			a.jmp(x86::eax);

			BYTE* shellcode = a.bufferData();
			UINT codesize = (UINT)holder.codeSize();

			memcpy_s(buffer, codesize, shellcode, codesize);
			peinfo.PointerOfWingSeciton += codesize;
		}
	}

	LPVOID CWingProtect::AllocPageSizeMemory()
	{
		auto l = VirtualAlloc(NULL, PageSize, MEM_COMMIT, PAGE_READWRITE);
		if (l) memset(l, 0, PageSize);
		return l;
	}

	ParserError CWingProtect::GetLastErr()
	{
		return _lasterror;
	}

	BOOL CWingProtect::IsSuccess()
	{
		return _lasterror == ParserError::Success;
	}

	BOOL CWingProtect::IsEnableIATEncrypt()
	{
		return EnableIATEncrypt == TRUE && _lasterror == ParserError::Success;
	}

	BOOL CWingProtect::Proctect(UINT protections)
	{
		auto ret = TRUE;
		auto reloc = peinfo.OptionalHeaderDllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		auto antidebug = ProtectionsHasFlag(protections,Protections::AnitDebug);
		auto fakecode = ProtectionsHasFlag(protections, Protections::JunkCode);

		if (EnableIATEncrypt && ProtectionsHasFlag(protections, Protections::IATEncrypt))
		{
			ret &= IATEncrypt(antidebug,fakecode);
		}

		DestoryRelocation();
		ProcessTLS(ProtectionsHasFlag(protections, Protections::TLSEncrypt));

		if (ProtectionsHasFlag(protections, Protections::XOREncrypt))
		{
			ret &= XORCodeSection(reloc, fakecode);
			reloc = FALSE;
		}

		if (ProtectionsHasFlag(protections, Protections::Compress))
		{
			ret &= CompressSeciton(reloc,fakecode);
			reloc = FALSE;		
		}

		//�����ݱ��������� ShellCode
		GenerateLoadingShellCode(protections, fakecode);

		return ret;
	}

	ParserError CWingProtect::ParsePE()
	{
		if (!PathFileExists(_filename))
		{
			return ParserError::FileNotFound;
		}

		if (PathIsDirectory(_filename))
		{
			return ParserError::InvalidFile;
		}

		hfile = CreateFile(_filename, FILE_READ_ACCESS, FILE_SHARE_WRITE | FILE_SHARE_READ,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hfile == INVALID_HANDLE_VALUE)
		{
			return ParserError::OpenFileError;
		}

		GetFileSizeEx(hfile, &peinfo.FileSize);

		hmap = CreateFileMapping(hfile, NULL, PAGE_READONLY, NULL, NULL, NULL);
		if (!hmap)
		{
			return ParserError::FileMappingError;
		}

		mapping = MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, 0);
		if (!mapping)
		{
			return ParserError::MapViewOfFileError;
		}

		auto dosHeader = (PIMAGE_DOS_HEADER)mapping;
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return ParserError::InvalidPE;
		}

		peinfo.ntHeaderOffset = dosHeader->e_lfanew;

		auto ntHeader = (PIMAGE_NT_HEADERS)OFFSET(mapping, dosHeader->e_lfanew);
		if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			return ParserError::InvalidPE;
		}

		auto bits = *(WORD*)OFFSET(ntHeader, sizeof(DWORD) + IMAGE_SIZEOF_FILE_HEADER);
		switch (bits)
		{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			return Parse32(ntHeader);
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			return Parse64(ntHeader);
		default:
			return ParserError::InvalidPE;
		}

		return ParserError::Success;
	}
	ParserError CWingProtect::Parse32(PIMAGE_NT_HEADERS ntHeader)
	{
		is64bit = FALSE;
		auto nt = (PIMAGE_NT_HEADERS32)ntHeader;
		peinfo.PNumberOfSections = (INT3264)&nt->FileHeader.NumberOfSections;
		auto f = nt->FileHeader;
		peinfo.NumberOfSections = f.NumberOfSections;

		peinfo.PAddressOfEntryPoint = (INT3264)&nt->OptionalHeader.AddressOfEntryPoint;
		peinfo.PSizeOfImage = (INT3264)&nt->OptionalHeader.SizeOfImage;
		peinfo.PSizeOfHeaders = (INT3264)&nt->OptionalHeader.SizeOfHeaders;
		auto o = nt->OptionalHeader;
		peinfo.AddressOfEntryPoint = o.AddressOfEntryPoint;
		peinfo.Subsystem = o.Subsystem;

		if (o.Subsystem == 1)
			return ParserError::DriverUnsupport;

		peinfo.FileAlignment = o.FileAlignment;
		peinfo.SectionAlignment = o.SectionAlignment;
		peinfo.ImageBase = o.ImageBase;
		peinfo.SizeOfImage = o.SizeOfImage;
		peinfo.SizeOfHeaders = o.SizeOfHeaders;
		peinfo.POptionalHeaderDllCharacteristics = &nt->OptionalHeader.DllCharacteristics;
		return ParserDir(ntHeader);
	}

	ParserError CWingProtect::Parse64(PIMAGE_NT_HEADERS ntHeader)
	{
		is64bit = TRUE;
		auto nt = (PIMAGE_NT_HEADERS64)ntHeader;

		peinfo.PNumberOfSections = (INT3264)&nt->FileHeader.NumberOfSections;
		auto f = nt->FileHeader;
		peinfo.NumberOfSections = f.NumberOfSections;

		peinfo.PAddressOfEntryPoint = (INT3264)&nt->OptionalHeader.AddressOfEntryPoint;
		peinfo.PSizeOfImage = (INT3264)&nt->OptionalHeader.SizeOfImage;
		peinfo.PSizeOfHeaders = (INT3264)&nt->OptionalHeader.SizeOfHeaders;
		peinfo.POptionalHeaderDllCharacteristics = &nt->OptionalHeader.DllCharacteristics;
		auto o = nt->OptionalHeader;
		peinfo.AddressOfEntryPoint = o.AddressOfEntryPoint;
		peinfo.Subsystem = o.Subsystem;

		if (o.Subsystem == 1)
			return ParserError::DriverUnsupport;

		peinfo.FileAlignment = o.FileAlignment;
		peinfo.SectionAlignment = o.SectionAlignment;
		peinfo.ImageBase = o.ImageBase;
		peinfo.SizeOfImage = o.SizeOfImage;
		peinfo.SizeOfHeaders = o.SizeOfHeaders;
		peinfo.OptionalHeaderDllCharacteristics = o.DllCharacteristics;

		return ParserDir(ntHeader);
	}

	ParserError CWingProtect::ParserDir(PIMAGE_NT_HEADERS ntHeader)
	{
		auto s = IMAGE_FIRST_SECTION(ntHeader);
		peinfo.PSectionHeaders = s;
		auto dd = (INT3264)s - (IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY));
		peinfo.PDataDirectory = (PIMAGE_DATA_DIRECTORY)dd;

		auto pdtls = peinfo.PDataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (pdtls.VirtualAddress && pdtls.Size)
			HasTLS = TRUE;

		auto pos = peinfo.AddressOfEntryPoint;
		auto pis = encryptInfo.OldImportDataAddr = peinfo.PDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

		DWORD maxVirual = 0;
		DWORD sizeraw = 0;
		for (UINT i = 0; i < peinfo.NumberOfSections; i++)
		{
			auto psh = s[i];
			if (psh.VirtualAddress <= pos && pos <= psh.VirtualAddress + psh.SizeOfRawData)
			{
				peinfo.PCodeSection = &s[i];
			}

			if (psh.VirtualAddress <= pis && pis <= psh.VirtualAddress + psh.SizeOfRawData)
			{
				peinfo.PImportSection = &s[i];
			}

			if (psh.VirtualAddress > maxVirual)
			{
				maxVirual = psh.VirtualAddress;
				sizeraw = psh.SizeOfRawData;
			}
		}

		auto d = div((INT3264)(maxVirual + sizeraw), peinfo.SectionAlignment);
		peinfo.AnalysisInfo.MinAvailableVirtualAddress = (UINT)(GetBiggerQuot(d) * peinfo.SectionAlignment);
		peinfo.AnalysisInfo.SectionsCanAddCount = (peinfo.SizeOfHeaders - (UINT)GETOFFSET(mapping, s)) / IMAGE_SIZEOF_SECTION_HEADER - peinfo.NumberOfSections - 1;
		auto pdd = (PIMAGE_DATA_DIRECTORY)dd;
		auto idd = pdd[IMAGE_DIRECTORY_ENTRY_IMPORT];

		auto pidd = (PIMAGE_IMPORT_DESCRIPTOR)GetPointerByRVA(mapping, idd.VirtualAddress);
		peinfo.PImportDescriptor = pidd;
		IMAGE_IMPORT_DESCRIPTOR iid = pidd[0];

		auto pdll = peinfo.AnalysisInfo.ImportDllName;
		auto pfunhint = peinfo.AnalysisInfo.ImportFunNameTable;
		auto pdiat = peinfo.AnalysisInfo.DllFirstThunks;
		if (is64bit)
		{
			int i = 0, ii = 0, itotal = 0;

			if (itotal >= MAXImportFunHintCount)
				return ParserError::TooManyImportFunctions;

			if (i >= MAXDllNameCount)
				return ParserError::TooManyImportDlls;

			while (iid.Characteristics)
			{
				pdll[i].Name = iid.Name;
				pdiat[i] = iid.FirstThunk;

				PIMAGE_THUNK_DATA64 pitd32 =
					(PIMAGE_THUNK_DATA64)GetPointerByRVA(mapping, iid.FirstThunk);
				IMAGE_THUNK_DATA64 itd32 = pitd32[0];
				PIMAGE_IMPORT_BY_NAME iibn;

				ii = 0;
				while (itd32.u1.AddressOfData)
				{
					if (!IMAGE_SNAP_BY_ORDINAL64(itd32.u1.AddressOfData))
					{
						iibn = (PIMAGE_IMPORT_BY_NAME)GetPointerByRVA(mapping, itd32.u1.AddressOfData);

						auto c = (char*)&iibn->Name;
						auto le = strlen(c);

						strcpy_s(pfunhint, PageSize, c);		//͵��д��
						pfunhint += (le + 1);
					}
					ii++;
					itd32 = pitd32[ii];
				}
				pdll[i].FunCount = ii;
				itotal += ii;
				i++;
				iid = pidd[i];
			}

			peinfo.AnalysisInfo.ImportDllCount = i;
			peinfo.AnalysisInfo.ImportFunCount = itotal;
			peinfo.AnalysisInfo.PointerofImportFunNameTable =
				(UINT)GETOFFSET(peinfo.AnalysisInfo.ImportFunNameTable, pfunhint);
		}
		else
		{
			int i = 0, ii = 0, itotal = 0;

			while (iid.Characteristics)
			{
				pdll[i].Name = iid.Name;
				pdiat[i] = iid.FirstThunk;

				PIMAGE_THUNK_DATA32 pitd32 =
					(PIMAGE_THUNK_DATA32)GetPointerByRVA(mapping, iid.FirstThunk);
				IMAGE_THUNK_DATA32 itd32 = pitd32[0];
				PIMAGE_IMPORT_BY_NAME iibn;

				ii = 0;
				while (itd32.u1.AddressOfData)
				{
					if (!IMAGE_SNAP_BY_ORDINAL64(itd32.u1.AddressOfData))
					{
						iibn = (PIMAGE_IMPORT_BY_NAME)GetPointerByRVA(mapping, itd32.u1.AddressOfData);

						auto c = (char*)&iibn->Name;
						auto le = strlen(c);

						strcpy_s(pfunhint, PageSize, c);		//͵��д��
						pfunhint += (le + 1);
					}

					ii++;
					itd32 = pitd32[ii];
				}
				pdll[i].FunCount = ii;
				itotal += ii;
				i++;
				iid = pidd[i];
			}

			peinfo.AnalysisInfo.ImportDllCount = i;
			peinfo.AnalysisInfo.ImportFunCount = itotal;
			peinfo.AnalysisInfo.PointerofImportFunNameTable =
				(UINT)GETOFFSET(peinfo.AnalysisInfo.ImportFunNameTable, pfunhint);
		}

		return  ParserError::Success;
	}

	BOOL CWingProtect::XORCodeSection(BOOL NeedReloc, BOOL FakeCode)
	{
		using namespace asmjit;

		if (_lasterror != ParserError::Success) return FALSE;

		auto filesize = peinfo.FileSize.QuadPart;

		CodeHolder holder;

		/// <summary>
		/// PointerToRawData
		/// </summary>
		auto p = peinfo.PCodeSection->PointerToRawData;

		/// <summary>
		/// SizeOfRawData
		/// </summary>
		auto sizecode = peinfo.PCodeSection->SizeOfRawData;

		//��ȡʣ��ռ�
		auto b = (BYTE*)GetPointerByRVA(packedPE, p);
		auto repeat = sizecode;

		BYTE* shellcode;
		INT3264 ccount;

		if (is64bit)
		{
			Environment env(Arch::kX64);
			holder.init(env);
			x86::Assembler a(&holder);
			Label loop = a.newLabel();

			x86::Mem mem;
			mem.setSegment(x86::gs);
			mem.setOffset(0x60);

			//���ɼ��� shellcode���˴��� rax = ImageBase
			a.push(x86::rcx);
			a.push(x86::rdi);

			//xor ����
			a.mov(x86::rax, mem);
			a.mov(x86::rax, x86::qword_ptr(x86::rax, 0x10));
			a.mov(x86::rdi, x86::rax);
			a.add(x86::rdi, peinfo.PCodeSection->VirtualAddress);
			a.mov(x86::rcx, repeat);

			a.bind(loop);
			if (FakeCode) FakeProtect(a);
			a.xor_(x86::byte_ptr(x86::rdi), 0x55);
			a.inc(x86::rdi);
			a.dec(x86::rcx);
			a.test(x86::rcx, x86::rcx);
			a.jnz(loop);

			//ȷ����ʱ rax �� eax ��ŵ��� ImageBase ��������δ������Ϊ
			if (NeedReloc)
				RelocationSection(a);

			a.pop(x86::rdi);
			a.pop(x86::rcx);

			a.ret();

			shellcode = a.bufferData();
			ccount = holder.codeSize();
		}
		else
		{
			Environment env(Arch::kX86);
			holder.init(env);
			x86::Assembler a(&holder);
			Label loop = a.newLabel();

			x86::Mem mem;
			mem.setSegment(x86::fs);
			mem.setOffset(0x30);

			//���ɼ��� shellcode
			a.push(x86::ecx);
			a.push(x86::edi);
			a.mov(x86::eax, mem);
			a.mov(x86::eax, x86::dword_ptr(x86::eax, 0x8));
			a.mov(x86::edi, x86::eax);
			a.add(x86::edi, peinfo.PCodeSection->VirtualAddress);
			a.mov(x86::ecx, repeat);

			a.bind(loop);
			if (FakeCode) FakeProtect(a);
			a.xor_(x86::byte_ptr(x86::edi), 0x55);
			a.inc(x86::edi);
			a.dec(x86::ecx);
			a.test(x86::ecx, x86::ecx);
			a.jnz(loop);

			//ȷ����ʱ rax �� eax ��ŵ��� ImageBase ��������δ������Ϊ
			if (NeedReloc)
				RelocationSection(a);

			a.pop(x86::edi);
			a.pop(x86::ecx);

			a.ret();

			shellcode = a.bufferData();
			ccount = holder.codeSize();
		}

		//������
		auto se = (BYTE*)b;
		for (UINT i = 0; i < repeat; i++)
		{
			se[i] ^= (BYTE)0x55;
		}

		//������ϣ�д Shellcode
		encryptInfo.XORDecodeShellCode = (UINT)peinfo.PointerOfWingSeciton;
		auto ws = GetPointerByOffset(peinfo.WingSecitonBuffer, peinfo.PointerOfWingSeciton);
		memcpy_s(ws, ccount, shellcode, ccount);
		peinfo.PointerOfWingSeciton += ccount;

		if (!NeedReloc)
		{
			auto tmp = (PIMAGE_SECTION_HEADER)TranModPEWapper(peinfo.PCodeSection);
			tmp->Characteristics |= IMAGE_SCN_MEM_WRITE;
		}

		return TRUE;
	}

	BOOL CWingProtect::CompressSeciton(BOOL NeedReloc, BOOL FakeCode)
	{

		using namespace asmjit;

		if (_lasterror != ParserError::Success) return FALSE;

#pragma pack(1)
		struct codata
		{
			BYTE code;
			BYTE count;
		} cdata{};
#pragma pack()

		list<codata> datas;
		auto p = (BYTE*)OFFSET(packedPE, peinfo.PCodeSection->PointerToRawData);
		auto length = peinfo.PCodeSection->SizeOfRawData;
		CodeHolder holder;
		CodeHolder jmpholder;

		//��ʼ����ѹ��
		for (UINT i = 0; i < length; i++, p++)
		{
			cdata.count = 1;
			cdata.code = *p;
			while (true)
			{
				if (cdata.count < 0xFF && i + 1 < length && *(p + 1) == cdata.code)
				{
					cdata.count++;
					i++;
					p++;
				}
				else
				{
					datas.push_back(cdata);
					break;
				}
			}
		}

		auto wingSection = peinfo.WingSection;
		auto buffer = GetPointerByOffset(peinfo.WingSecitonBuffer, peinfo.PointerOfWingSeciton);
		encryptInfo.CompressedData = (UINT)peinfo.PointerOfWingSeciton;

		BYTE* shellcode;
		INT3264 codesize;
		INT3264 datasize;

		Environment envX64(Arch::kX64);

		// gs:[0x60]
		x86::Mem memX64;
		memX64.setSegment(x86::gs);
		memX64.setOffset(0x60);

		Environment envX86(Arch::kX86);
		//	fs:[0x30]
		x86::Mem memX86;
		memX86.setSegment(x86::fs);
		memX86.setOffset(0x30);

		auto rvabase = peinfo.AnalysisInfo.MinAvailableVirtualAddress;
#define AddRVABase(offset) ((UINT)offset + (UINT)rvabase)

		if (is64bit)
		{
			//���ɻ�����
			holder.init(envX64);
			x86::Assembler a(&holder);
			Label loop = a.newLabel();
			Label loop_d = a.newLabel();

			a.push(x86::rsi);
			a.push(x86::rdi);
			a.push(x86::rcx);
			a.push(x86::rdx);

			a.mov(x86::rax, memX64);
			a.mov(x86::rdx, x86::qword_ptr(x86::rax, 0x10));

			a.mov(x86::rsi, AddRVABase(encryptInfo.CompressedData));
			a.add(x86::rsi, x86::rdx);
			a.mov(x86::rdi, peinfo.PCodeSection->VirtualAddress);
			a.add(x86::rdi, x86::rdx);

			a.mov(x86::rcx, x86::qword_ptr(x86::rsi));
			a.add(x86::rsi, 8);

			a.xor_(x86::eax, x86::eax);

			a.bind(loop);
			a.mov(x86::ax, x86::word_ptr(x86::rsi));

			a.bind(loop_d);
			if (FakeCode) FakeProtect(a);
			a.mov(x86::byte_ptr(x86::rdi), x86::al);
			a.inc(x86::rdi);
			a.dec(x86::ah);
			a.test(x86::ah, x86::ah);
			a.jnz(loop_d);
			a.add(x86::rsi, 2);
			a.dec(x86::rcx);
			a.test(x86::rcx, x86::rcx);
			a.jnz(loop);

			a.mov(x86::rax, x86::rdx);	//��ʱִ����Ϻ� rax ��ŵ��� ImageBase
			a.pop(x86::rdx);
			a.pop(x86::rcx);
			a.pop(x86::rdi);
			a.pop(x86::rsi);

			//ȷ����ʱ rax �� eax ��ŵ��� ImageBase ��������δ������Ϊ
			if (NeedReloc)
				RelocationSection(a);

			a.ret();

			shellcode = a.bufferData();
			codesize = holder.codeSize();
			datasize = datas.size() * sizeof(codata) + sizeof(INT64);
		}
		else
		{
			holder.init(envX86);
			x86::Assembler a(&holder);
			Label loop = a.newLabel();
			Label loop_d = a.newLabel();

			a.push(x86::esi);
			a.push(x86::edi);
			a.push(x86::ecx);
			a.push(x86::edx);

			a.mov(x86::eax, memX86);
			a.mov(x86::edx, x86::qword_ptr(x86::eax, 0x8));

			a.mov(x86::esi, AddRVABase(encryptInfo.CompressedData));
			a.add(x86::esi, x86::edx);
			a.mov(x86::edi, peinfo.PCodeSection->VirtualAddress);
			a.add(x86::edi, x86::edx);

			a.mov(x86::ecx, x86::dword_ptr(x86::esi));
			a.add(x86::esi, 8);

			a.xor_(x86::eax, x86::eax);

			a.bind(loop);
			a.mov(x86::ax, x86::word_ptr(x86::rsi));

			a.bind(loop_d);
			if (FakeCode) FakeProtect(a);
			a.mov(x86::byte_ptr(x86::edi), x86::al);
			a.inc(x86::edi);
			a.dec(x86::ah);
			a.test(x86::ah, x86::ah);
			a.jnz(loop_d);
			a.add(x86::esi, 2);
			a.dec(x86::ecx);
			a.test(x86::ecx, x86::ecx);
			a.jnz(loop);

			a.mov(x86::eax, x86::edx);	//��ʱִ����Ϻ� rax ��ŵ��� ImageBase
			a.pop(x86::edx);
			a.pop(x86::ecx);
			a.pop(x86::edi);
			a.pop(x86::esi);

			//ȷ����ʱ rax �� eax ��ŵ��� ImageBase ��������δ������Ϊ
			if (NeedReloc)
				RelocationSection(a);

			a.ret();

			shellcode = a.bufferData();
			codesize = holder.codeSize();
			datasize = datas.size() * sizeof(codata) + sizeof(INT32);
		}

		encryptInfo.ShellCodeDeCompress = (UINT)(encryptInfo.CompressedData + datasize);
		peinfo.PointerOfWingSeciton += (datasize + codesize);

		codata* pc;

		if (is64bit)
		{
			auto bd = (INT64*)buffer;
			*bd = (INT64)datas.size();
			pc = (codata*)(bd + 1);
		}
		else
		{
			auto bd = (INT32*)buffer;	
			*bd = (INT32)datas.size();
			pc = (codata*)(bd + 1);
		}

		//��������
		for (auto i = datas.begin(); i != datas.end(); i++, pc++)
		{
			*pc = *i;
		}

		memcpy_s(pc, codesize, shellcode, codesize);		//���� shellcode

		//��մ����
		::memset((LPVOID)OFFSET(packedPE, peinfo.PCodeSection->PointerToRawData), 0, peinfo.PCodeSection->SizeOfRawData);

		auto tmp = (PIMAGE_SECTION_HEADER)TranModPEWapper(peinfo.PCodeSection);
		tmp->Characteristics |= IMAGE_SCN_MEM_WRITE;

		return TRUE;
	}

	BOOL CWingProtect::IATEncrypt(BOOL AntiDebug, BOOL FakeCode)
	{
		using namespace asmjit;

		auto dlls = peinfo.AnalysisInfo.ImportDllName;

		// ImportDllCount
		auto dllcount = peinfo.AnalysisInfo.ImportDllCount;
		// ImportFunCount
		auto funcount = peinfo.AnalysisInfo.ImportFunCount;

		vector<string> DllNames;		//���� ����Dll �洢�б�
		auto stringsSize = 0UL;
		for (UINT i = 0; i < dllcount; i++)
		{
			auto name = GetStringFormRVA(mapping, dlls[i].Name);
			stringsSize += (ULONG)name.size();
			DllNames.push_back(name);
		}

		auto wingSection = peinfo.WingSection;
		LPVOID wing = peinfo.WingSecitonBuffer;

		auto filesize = peinfo.FileSize.QuadPart;

		//������Ҫ������Լ�����
		auto nd = (PIMAGE_IMPORT_DESCRIPTOR)wing;

		auto rvabase = peinfo.AnalysisInfo.MinAvailableVirtualAddress;

		char kernel32[] = "KERNEL32.dll";
		char getproc[] = "GetProcAddress";
		char loadlib[] = "LoadLibraryA";

#define AddRVABase(offset) ((UINT)offset + (UINT)rvabase)

		if (is64bit)
		{
			auto nt = (PIMAGE_THUNK_DATA64)(nd + 2);
			auto nin = (PIMAGE_IMPORT_BY_NAME)(nt + 3);		//�ճ�һ����ʾ����
			auto b = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2 + sizeof(IMAGE_THUNK_DATA64) * 3;

			nd->FirstThunk = nd->OriginalFirstThunk = AddRVABase(GETOFFSET(wing, nt));

			nt[0].u1.AddressOfData = AddRVABase(b);				//��һ�� IMAGE_IMPORT_BY_NAME

			nin->Hint = 0x2B6;		//GetProcAddress
			auto l = sizeof(getproc);
			memcpy_s(&nin->Name, l, getproc, l);
			b += (sizeof(IMAGE_IMPORT_BY_NAME) + l);

			nin = (PIMAGE_IMPORT_BY_NAME)OFFSET(wing, b);		//ָ����һ�� IMAGE_IMPORT_BY_NAME

			nt[1].u1.AddressOfData = AddRVABase(b);

			nin->Hint = 0x3C5;		//LoadLibraryA
			l = sizeof(loadlib);
			memcpy_s(&nin->Name, l, loadlib, l);
			b += (sizeof(IMAGE_IMPORT_BY_NAME) + l);

			auto p = (char*)OFFSET(wing, b);		//ָ��ʣ��ռ�
			l = sizeof(kernel32);
			memcpy_s(p, l, kernel32, l);
			nd->Name = AddRVABase(b);
			p += l;

			//��Ϣ������ϣ���ʼ����������Ŀ

			//Ϊ��ַ���ṩ�ռ䣬��ʱ b = rva

			//�� IAT ��λ��
			encryptInfo.NewIATAddr = (UINT)(b + l);
			p += sizeof(INT64) * funcount;

			//ÿ��Dll�������������б��ַ
			encryptInfo.DllFunctionsCount = (UINT)GETOFFSET(wing, p);
			auto pdllt = (UINT*)p;
			auto d = peinfo.AnalysisInfo.ImportDllName;

			//���Ÿ�����
			for (int i = dllcount - 1; i >= 0; i--, pdllt++)
			{
				*pdllt = d[i].FunCount;
			}

			//�µ� Dll ����
			encryptInfo.ImportDllNames = (UINT)GETOFFSET(wing, pdllt);
			auto pchar = (char*)pdllt;
			for (UINT i = 0; i < dllcount; i++)
			{
				string item = DllNames[i];
				item.copy(pchar, item.length());
				pchar += (item.length() + 1);
			}

			DllNames.clear();	//������ϣ����

			encryptInfo.ImportFuctionNameTable = (UINT)GETOFFSET(wing, pchar);
			UINT hintsize = peinfo.AnalysisInfo.PointerofImportFunNameTable;

			memcpy_s(pchar, hintsize, peinfo.AnalysisInfo.ImportFunNameTable, hintsize);

			encryptInfo.FirstThunks = encryptInfo.ImportFuctionNameTable + hintsize;

			//�̶��� FirstThunks�����޸��׵�ַ��׼������
			pchar += hintsize;
			UINT fthunksize = sizeof(UINT) * dllcount;
			auto piat = (UINT*)pchar;
			for (UINT i = 0; i < dllcount; i++)
			{
				piat[i] = peinfo.AnalysisInfo.DllFirstThunks[dllcount - 1 - i];
			}

			encryptInfo.IATShellCode = encryptInfo.FirstThunks + fthunksize;
			pchar += fthunksize;

			//��һ������ shellcode

			Environment env(Arch::kX64);
			CodeHolder holder;

			// gs:[0x60]
			x86::Mem mem;
			mem.setSegment(x86::gs);
			mem.setOffset(0x60);

			holder.init(env);
			x86::Assembler a(&holder);
			Label loop_ft = a.newLabel();
			Label loop_ft_n = a.newLabel();
			Label LoadLibraryA_Err = a.newLabel();
			Label GetProcAddress_Err = a.newLabel();
			Label loop_p = a.newLabel();
			Label loop = a.newLabel();
			Label loop_str = a.newLabel();

			a.mov(x86::rax, mem);
			a.mov(x86::rax, x86::qword_ptr(x86::rax, 0x10));

			a.push(x86::rsi);
			a.push(x86::rdi);
			a.push(x86::rcx);
			a.push(x86::rdx);
			a.push(x86::r8);
			a.push(x86::r9);
			a.push(x86::r10);
			a.push(x86::r11);
			a.push(x86::r12);
			a.push(x86::r13);

			a.push(x86::r14);
			a.xor_(x86::r14, x86::r14);	//r14 ��Ϊ��д IAT ���������

			a.nop();
			//�޸�ԭ FirstThunks ��ַ
			a.mov(x86::r10d, dllcount);
			
			if(FakeCode) FakeProtect(a);

			a.mov(x86::rsi, x86::rax);
			a.mov(x86::rdi, x86::rax);
			a.add(x86::rsi, AddRVABase(encryptInfo.DllFunctionsCount));
			a.add(x86::rdi, AddRVABase(encryptInfo.FirstThunks));

			a.bind(loop_ft);
			a.dec(x86::r10d);
			a.mov(x86::ecx, x86::dword_ptr(x86::rsi, x86::r10d, 2));		//ָ�������ĸ�����ע���ǵ��ŵ�
			a.mov(x86::edx, x86::dword_ptr(x86::rdi, x86::r10d, 2));	//Ҫ�޸��� IAT���ַ
			a.add(x86::rdx, x86::rax);	//rdx = Thunk ��
			a.bind(loop_ft_n);

			a.dec(x86::ecx);
			a.add(x86::qword_ptr(x86::rdx, x86::ecx, 3), x86::rax);	//�޸���ַ
			a.cmp(x86::ecx, 0);
			a.ja(loop_ft_n);
			a.cmp(x86::r10d, 0);
			a.ja(loop_ft);

			a.nop();

			//��ȡ������ַ
			a.mov(x86::rcx, wingSection->VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2);
			a.add(x86::rcx, x86::rax);
			a.mov(x86::r12, x86::qword_ptr(x86::rcx, 8));		// LoadLibraryA
			a.mov(x86::r13, x86::qword_ptr(x86::rcx));		// GetProcAddress
			a.mov(x86::rdi, x86::rax);
			a.add(x86::rdi, AddRVABase(encryptInfo.NewIATAddr));		//edi = NewIATAddr

			a.mov(x86::r8d, dllcount);		//��ʱ r8 Ϊ Dll ����������
			a.mov(x86::r10, x86::rax);
			a.add(x86::r10, AddRVABase(encryptInfo.ImportDllNames));		//r10 Ϊ ImportDllNames


			a.mov(x86::r11d, AddRVABase(encryptInfo.ImportFuctionNameTable));
			a.add(x86::r11, x86::rax);
			//�Դ�֮�󣬷ϵ� rax ��Ϊ ImageBase �����

			a.bind(loop);
			a.dec(x86::r8d);

			SaveEasyLostReg64(a);
			a.sub(x86::rsp, 0x20);		//fastcall needed���ڼ䲻Ҫ����Ӱ���ջ�Ĳ���

			//���ε��� LoadLibraryA
			a.mov(x86::rcx, x86::r10);
			if (FakeCode) FakeProtect(a);
			a.call(x86::r12);

			a.test(x86::rax, x86::rax);
			a.jnz(LoadLibraryA_Err);
			a.int3();		//�׳�һ���쳣
			a.bind(LoadLibraryA_Err);

			a.add(x86::rsp, 0x20);		//fastcall needed 
			RestoreEasyLostReg64(a);

			a.mov(x86::r9d, x86::dword_ptr(x86::rsi, x86::r8d, 2));		//r9 = EachFunctionsCount

			//���濪ʼ��ȡ��ַ������д���ǵ� IAT ��
			a.bind(loop_p);
			a.dec(x86::r9);

			SaveEasyLostReg64(a);		//�������� r9 �ֲ�����
			a.push(x86::rax);

			a.mov(x86::rcx, x86::rax);
			a.sub(x86::rsp, 0x28);		//fastcall needed���ڼ䲻Ҫ����Ӱ���ջ�Ĳ���
			a.mov(x86::rdx, x86::r11);

			if (FakeCode) FakeProtect(a);			
			a.call(x86::r13);
			a.test(x86::rax, x86::rax);
			a.jnz(GetProcAddress_Err);
			a.int3();		//�׳�һ���쳣
			a.bind(GetProcAddress_Err);

			a.nop();
			a.push(x86::rdi);
			a.mov(x86::rdi, mem);
			a.mov(x86::rdi, x86::qword_ptr(x86::rdi, 0x10));
			a.add(x86::rdi, AddRVABase(encryptInfo.NewIATAddr));		//edi = NewIATAddr
			a.mov(x86::qword_ptr(x86::rdi, x86::r14, 3), x86::rax);
			a.pop(x86::rdi);
			a.add(x86::rsp, 0x28);		//fastcall needed 	

			a.pop(x86::rax);
			RestoreEasyLostReg64(a);		//�ָ� r9 ������Ϊ�ֲ�������������

			//��������ַ����Ƶ���һ��
			a.push(x86::rax);
			a.push(x86::rcx);
			a.push(x86::edi);
			a.mov(x86::rdi, x86::r11);
			a.mov(x86::ecx, -1);
			a.xor_(x86::eax, x86::eax);
			a.repnz();
			a.scasb();
			a.mov(x86::r11, x86::rdi);
			a.pop(x86::rcx);
			a.pop(x86::edi);
			a.pop(x86::rax);
			a.nop();
			a.inc(x86::r14);
			a.nop();
			a.cmp(x86::r9, 0);
			a.ja(loop_p);

			//���ַ����ƶ�����һ���ַ���
			a.nop();
			a.push(x86::rax);
			a.push(x86::rcx);
			a.push(x86::edi);
			a.mov(x86::rdi, x86::r10);
			a.mov(x86::ecx, -1);
			a.xor_(x86::eax, x86::eax);
			a.repnz();
			a.scasb();
			a.mov(x86::r10, x86::rdi);
			a.pop(x86::rcx);
			a.pop(x86::edi);
			a.pop(x86::rax);

			a.cmp(x86::r8d, 0);
			a.ja(loop);

			a.pop(x86::r14);
			a.pop(x86::r13);
			a.pop(x86::r12);
			a.pop(x86::r11);
			a.pop(x86::r10);
			a.pop(x86::r9);
			a.pop(x86::r8);
			a.pop(x86::rdx);
			a.pop(x86::rcx);
			a.pop(x86::rdi);
			a.pop(x86::rsi);

			a.ret();

			auto DispatcherFunction = encryptInfo.IATShellCode + holder.codeSize();

			//�����ɷ�����
			a.pop(x86::rax);		//��ȡ������
			a.push(x86::rdx);
			a.push(x86::rcx);
			a.mov(x86::rdx, x86::rax);	// rdx Ϊ������

			a.mov(x86::rax, mem);
			a.mov(x86::rcx, x86::qword_ptr(x86::rax, 0x10));
			a.add(x86::rcx, AddRVABase(encryptInfo.NewIATAddr));

			a.mov(x86::rax, x86::qword_ptr(x86::rcx, x86::rdx, 3));

			if (AntiDebug)
			{
				Label anti = a.newLabel();

				a.mov(x86::dl, x86::byte_ptr(x86::rax));
				a.cmp(x86::dl, 0xCC);
				a.jne(anti);
				a.xor_(x86::rax, 0x11);
				a.bind(anti);
			}

			a.pop(x86::rcx);
			a.pop(x86::rdx);
			a.jmp(x86::rax);
			a.nop();

			//���ɵ�����ں���

			vector<UINT> entryRVA;

			for (UINT i = 0; i < funcount; i++)
			{
				entryRVA.push_back(AddRVABase(encryptInfo.IATShellCode + (UINT)holder.codeSize()));
				a.mov(x86::rax, mem);
				a.mov(x86::rax, x86::qword_ptr(x86::rax, 0x10));
				a.push(x86::rsi);
				a.mov(x86::rsi, AddRVABase(DispatcherFunction));	//�ɷ����� RVA
				a.add(x86::rsi, x86::rax);
				a.xchg(x86::rsi, x86::rax);
				a.pop(x86::rsi);
				a.push(i);
				if (FakeCode) FakeProtect(a);
				a.jmp(x86::rax);
				a.nop();
			}

			BYTE* shellcode = a.bufferData();
			UINT codesize = (UINT)holder.codeSize();

			memcpy_s(pchar, codesize, shellcode, codesize);
			pchar += codesize;

			//��дԭ IAT ��ַΪ���ɷ������� RVA����Ĩ���ۼ�
			auto pi = (PIMAGE_IMPORT_DESCRIPTOR)TranModPEWapper(peinfo.PImportDescriptor);

			UINT funi = 0;
			auto ec = peinfo.AnalysisInfo.ImportDllName;
			for (UINT i = 0; i < dllcount; i++, pi++)
			{
				auto pitem = (UINT64*)GetPointerByRVA(packedPE, pi->FirstThunk);
				auto opitem = (UINT64*)GetPointerByRVA(packedPE, pi->OriginalFirstThunk);
				for (UINT ii = 0; ii < ec[i].FunCount; ii++, funi++)
				{
					pitem[ii] = entryRVA[funi];
					opitem[ii] = 0;	//Ĩ�����õ� OriginalFirstThunk ��͵������������Ĳ���
				}
				pi->OriginalFirstThunk = 0;		//��Ĩ���ۼ�
			}

			entryRVA.clear();		//�������

			//��ȡ������ʹ�õ�ռ�ô�С�������ۼ�
			auto totallen = (UINT)GETOFFSET(wing, pchar);
			peinfo.PointerOfWingSeciton += totallen;
			ImportTableNeedCorrent = TRUE;

		}
		else
		{
			auto nt = (PIMAGE_THUNK_DATA32)(nd + 2); //�ճ�һ����ʾ����
			auto nin = (PIMAGE_IMPORT_BY_NAME)(nt + 3);		//�ճ�һ����ʾ����
			auto b = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2 + sizeof(IMAGE_THUNK_DATA32) * 3;

			nd->FirstThunk = nd->OriginalFirstThunk = AddRVABase(GETOFFSET(wing, nt));

			nt[0].u1.AddressOfData = AddRVABase(b);				//��һ�� IMAGE_IMPORT_BY_NAME

			nin->Hint = 0x2B6;		//GetProcAddress
			auto l = sizeof(getproc);
			memcpy_s(&nin->Name, l, getproc, l);
			b += (sizeof(IMAGE_IMPORT_BY_NAME) + l);

			nin = (PIMAGE_IMPORT_BY_NAME)OFFSET(wing, b);		//ָ����һ�� IMAGE_IMPORT_BY_NAME

			nt[1].u1.AddressOfData = AddRVABase(b);

			nin->Hint = 0x3C5;		//LoadLibraryA
			l = sizeof(loadlib);
			memcpy_s(&nin->Name, l, loadlib, l);
			b += (sizeof(IMAGE_IMPORT_BY_NAME) + l);

			auto p = (char*)OFFSET(wing, b);		//ָ��ʣ��ռ�
			l = sizeof(kernel32);
			memcpy_s(p, l, kernel32, l);
			nd->Name = AddRVABase(b);
			p += l;

			//��Ϣ������ϣ���ʼ����������Ŀ

			//Ϊ��ַ���ṩ�ռ䣬��ʱ b = rva

			//�� IAT ��λ��
			encryptInfo.NewIATAddr = (UINT)(b + l);
			p += sizeof(INT32) * funcount;

			//ÿ��Dll�������������б��ַ
			encryptInfo.DllFunctionsCount = (UINT)GETOFFSET(wing, p);
			auto pdllt = (UINT*)p;
			auto d = peinfo.AnalysisInfo.ImportDllName;

			//���Ÿ�����
			for (int i = dllcount - 1; i >= 0; i--, pdllt++)
			{
				*pdllt = d[i].FunCount;
			}

			//�µ� Dll ����
			encryptInfo.ImportDllNames = (UINT)GETOFFSET(wing, pdllt);
			auto pchar = (char*)pdllt;
			for (UINT i = 0; i < dllcount; i++)
			{
				string item = DllNames[i];
				item.copy(pchar, item.length());
				pchar += (item.length() + 1);
			}

			DllNames.clear();	//������ϣ����

			encryptInfo.ImportFuctionNameTable = (UINT)GETOFFSET(wing, pchar);
			UINT hintsize = peinfo.AnalysisInfo.PointerofImportFunNameTable;

			memcpy_s(pchar, hintsize, peinfo.AnalysisInfo.ImportFunNameTable, hintsize);

			encryptInfo.FirstThunks = encryptInfo.ImportFuctionNameTable + hintsize;

			//�̶��� FirstThunks�����޸��׵�ַ��׼������
			pchar += hintsize;
			UINT fthunksize = sizeof(UINT) * dllcount;
			auto piat = (UINT*)pchar;
			for (UINT i = 0; i < dllcount; i++)
			{
				piat[i] = peinfo.AnalysisInfo.DllFirstThunks[dllcount - 1 - i];
			}

			encryptInfo.IATShellCode = encryptInfo.FirstThunks + fthunksize;
			pchar += fthunksize;

#define StackSize 0x10
#define LoadLibPointer x86::dword_ptr(x86::ebp, -4)
#define GetProcAddrPointer x86::dword_ptr(x86::ebp, -8)
#define EachFunctionCountPointer x86::dword_ptr(x86::ebp, -0xC)
#define EachFunctionCountTablePointer x86::dword_ptr(x86::ebp, -0x10)

			Environment env(Arch::kX86);
			CodeHolder holder;
			//	fs:[0x30]
			x86::Mem mem;
			mem.setSegment(x86::fs);
			mem.setOffset(0x30);

			holder.init(env);
			x86::Assembler a(&holder);
			Label loop_ft = a.newLabel();
			Label loop_ft_n = a.newLabel();
			Label LoadLibraryA_Err = a.newLabel();
			Label GetProcAddress_Err = a.newLabel();
			Label loop_p = a.newLabel();
			Label loop = a.newLabel();
			Label loop_str = a.newLabel();

			a.mov(x86::eax, mem);
			a.mov(x86::eax, x86::dword_ptr(x86::eax, 0x8));

			a.push(x86::ebp);
			a.mov(x86::ebp, x86::esp);
			a.sub(x86::esp, StackSize);
			a.pushad();

			a.nop();
			//�޸�ԭ FirstThunks ��ַ
			a.mov(x86::ebx, dllcount);
			a.mov(x86::esi, x86::eax);
			a.mov(x86::edi, x86::eax);
			a.add(x86::esi, AddRVABase(encryptInfo.DllFunctionsCount));
			a.mov(EachFunctionCountTablePointer, x86::esi);
			a.add(x86::edi, AddRVABase(encryptInfo.FirstThunks));

			a.bind(loop_ft);
			a.dec(x86::ebx);
			a.mov(x86::ecx, x86::dword_ptr(x86::esi, x86::ebx, 2));		//ָ�������ĸ�����ע���ǵ��ŵ�
			a.mov(x86::edx, x86::dword_ptr(x86::edi, x86::ebx, 2));	//Ҫ�޸��� IAT���ַ
			a.add(x86::edx, x86::eax);	//rdx = Thunk ��
			a.bind(loop_ft_n);

			a.dec(x86::ecx);
			a.add(x86::dword_ptr(x86::edx, x86::ecx, 2), x86::eax);	//�޸���ַ
			a.cmp(x86::ecx, 0);
			a.ja(loop_ft_n);
			a.cmp(x86::ebx, 0);
			a.ja(loop_ft);

			a.nop();

			//��ȡ������ַ
			a.mov(x86::ecx, wingSection->VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2);
			a.add(x86::ecx, x86::eax);
			a.mov(x86::ebx, x86::qword_ptr(x86::ecx, 4));		// LoadLibraryA
			a.mov(x86::edx, x86::qword_ptr(x86::ecx));		// GetProcAddress

			a.mov(LoadLibPointer, x86::ebx);		// LoadLibraryA
			a.mov(GetProcAddrPointer, x86::edx);		// GetProcAddress

			a.xor_(x86::ebx, x86::ebx);	//ebx ��Ϊ��д IAT ���������

			a.mov(x86::edi, x86::eax);
			a.add(x86::edi, AddRVABase(encryptInfo.NewIATAddr));		//edi = NewIATAddr

			// ecx ��һ���׶�ʹ�����

			a.mov(x86::ecx, dllcount);		//��ʱ ecx Ϊ Dll ����������
			a.mov(x86::esi, x86::eax);
			a.add(x86::esi, AddRVABase(encryptInfo.ImportDllNames));		//esi Ϊ ImportDllNames


			a.mov(x86::edx, AddRVABase(encryptInfo.ImportFuctionNameTable));	//edx Ϊ ImportFuctionNameTable
			a.add(x86::edx, x86::eax);

			//�Դ�֮�󣬷ϵ� eax ��Ϊ ImageBase �����

			a.bind(loop);
			a.dec(x86::ecx);

			SaveEasyLostReg32(a);

			//���ε��� LoadLibraryA
			a.push(x86::esi);
			a.call(LoadLibPointer);

			a.test(x86::eax, x86::eax);
			a.jnz(LoadLibraryA_Err);
			a.int3();		//�׳�һ���쳣
			a.bind(LoadLibraryA_Err);

			RestoreEasyLostReg32(a);

			a.push(x86::eax);
			a.push(x86::esi);
			a.mov(x86::esi, EachFunctionCountTablePointer);
			a.mov(x86::eax, x86::dword_ptr(x86::esi, x86::ecx, 2));
			a.mov(EachFunctionCountPointer, x86::eax);
			a.pop(x86::esi);
			a.pop(x86::eax);

			//���濪ʼ��ȡ��ַ������д���ǵ� IAT ��
			a.bind(loop_p);
			a.dec(EachFunctionCountPointer);

			//TODO��Ҫͨ�� Hint ��ȡ��������Ҫʵ��һ��

			a.push(x86::eax);		//���淵��ֵ����һ����

			SaveEasyLostReg32(a);
			a.push(x86::edx);
			a.push(x86::eax);	//����		
			a.call(GetProcAddrPointer);

			a.test(x86::eax, x86::eax);
			a.jnz(GetProcAddress_Err);
			a.int3();		//�׳�һ���쳣
			a.bind(GetProcAddress_Err);

			RestoreEasyLostReg32(a);

			a.push(x86::edi);
			a.mov(x86::edi, mem);
			a.mov(x86::edi, x86::dword_ptr(x86::edi, 0x8));
			a.add(x86::edi, AddRVABase(encryptInfo.NewIATAddr));		//edi = NewIATAddr
			a.mov(x86::dword_ptr(x86::edi, x86::ebx, 2), x86::eax);
			a.pop(x86::edi);

			a.pop(x86::eax);

			//��������ַ����Ƶ���һ��
			a.push(x86::eax);
			a.push(x86::ecx);
			a.push(x86::edi);
			a.mov(x86::edi, x86::edx);
			a.mov(x86::ecx, -1);
			a.xor_(x86::eax, x86::eax);
			a.repnz();
			a.scasb();
			a.mov(x86::edx, x86::edi);
			a.pop(x86::edi);
			a.pop(x86::ecx);
			a.pop(x86::eax);
			a.nop();
			a.inc(x86::ebx);
			a.nop();
			a.cmp(EachFunctionCountPointer, 0);
			a.ja(loop_p);

			//���ַ����ƶ�����һ���ַ���
			a.nop();
			a.push(x86::eax);
			a.push(x86::ecx);
			a.push(x86::edi);
			a.mov(x86::edi, x86::esi);
			a.mov(x86::ecx, -1);
			a.xor_(x86::eax, x86::eax);
			a.repnz();
			a.scasb();
			a.mov(x86::esi, x86::edi);
			a.pop(x86::edi);
			a.pop(x86::ecx);
			a.pop(x86::eax);

			a.cmp(x86::ecx, 0);
			a.ja(loop);

			a.popad();
			a.add(x86::esp, StackSize);
			a.pop(x86::ebp);

			a.ret();
			a.nop();

			auto DispatcherFunction = encryptInfo.IATShellCode + holder.codeSize();

			//�����ɷ�����
			a.pop(x86::eax);		//��ȡ������
			a.push(x86::edx);
			a.push(x86::ecx);
			a.mov(x86::edx, x86::eax);	// rdx Ϊ������

			a.mov(x86::eax, mem);
			a.mov(x86::ecx, x86::qword_ptr(x86::eax, 0x8));
			a.add(x86::ecx, AddRVABase(encryptInfo.NewIATAddr));

			a.mov(x86::eax, x86::dword_ptr(x86::ecx, x86::edx, 2));

			if (AntiDebug)
			{
				Label anti = a.newLabel();

				a.mov(x86::dl, x86::byte_ptr(x86::eax));
				a.cmp(x86::dl, 0xCC);
				a.jne(anti);
				a.xor_(x86::eax, 0x11);
				a.bind(anti);
			}

			a.pop(x86::ecx);
			a.pop(x86::edx);
			a.jmp(x86::eax);
			a.nop();

			//���ɵ�����ں���

			vector<UINT> entryRVA;

			for (UINT i = 0; i < funcount; i++)
			{
				entryRVA.push_back(AddRVABase(encryptInfo.IATShellCode + (UINT)holder.codeSize()));
				a.mov(x86::eax, mem);
				a.mov(x86::eax, x86::dword_ptr(x86::eax, 0x8));
				a.push(x86::esi);
				a.mov(x86::esi, AddRVABase(DispatcherFunction));	//�ɷ����� RVA
				a.add(x86::esi, x86::eax);
				a.xchg(x86::esi, x86::eax);
				a.pop(x86::esi);
				a.push(i);
				a.jmp(x86::eax);
				a.nop();
			}

			BYTE* shellcode = a.bufferData();
			UINT codesize = (UINT)holder.codeSize();

			memcpy_s(pchar, codesize, shellcode, codesize);
			pchar += codesize;

			//��дԭ IAT ��ַΪ���ɷ������� RVA����Ĩ���ۼ�
			auto pi = (PIMAGE_IMPORT_DESCRIPTOR)TranModPEWapper(peinfo.PImportDescriptor);

			UINT funi = 0;
			auto ec = peinfo.AnalysisInfo.ImportDllName;
			for (UINT i = 0; i < dllcount; i++, pi++)
			{
				auto pitem = (UINT32*)GetPointerByRVA(packedPE, pi->FirstThunk);
				auto opitem = (UINT32*)GetPointerByRVA(packedPE, pi->OriginalFirstThunk);
				for (UINT ii = 0; ii < ec[i].FunCount; ii++, funi++)
				{
					pitem[ii] = entryRVA[funi];
					opitem[ii] = 0;	//Ĩ�����õ� OriginalFirstThunk ��͵������������Ĳ���
				}
				pi->OriginalFirstThunk = 0;		//��Ĩ���ۼ�
			}

			entryRVA.clear();		//�������

			//��ȡ������ʹ�õ�ռ�ô�С�������ۼ�
			auto totallen = (UINT)GETOFFSET(wing, pchar);
			peinfo.PointerOfWingSeciton += totallen;
			ImportTableNeedCorrent = TRUE;
		}

		//������Ϻ��޸�����
		auto tmp = (PIMAGE_SECTION_HEADER)TranModPEWapper(peinfo.PImportSection);
		tmp->Characteristics |= IMAGE_SCN_MEM_WRITE;

		return TRUE;
	}


	/// <summary>
	/// �����ض�λ���룬ȷ����ʱ rax �� eax ��ŵ��� ImageBase ��������δ������Ϊ
	/// </summary>
	/// <param name="a"></param>
	void CWingProtect::RelocationSection(asmjit::x86::Assembler& a)
	{
		using namespace asmjit;

		Label loop_xor = a.newLabel();
		Label loop_reloc = a.newLabel();
		Label loop_rt = a.newLabel();
		Label endproc = a.newLabel();
		auto rdd = peinfo.PDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (is64bit)
		{
			a.nop();
			a.push(x86::rdi);
			a.push(x86::rcx);

			a.push(x86::rsi);		//���� rsi
			a.mov(x86::rsi, rdd.VirtualAddress);	//�ض�λ���ַ
			a.add(x86::rsi, x86::rax);

			a.push(x86::rdx);	//���� rdx

			a.push(x86::r10);
			a.mov(x86::r10, peinfo.ImageBase);	//PE ���غ󣬸�ֵ�ᱻ�ض�λ��ֻ��д��
			a.sub(x86::r10, x86::rax);
			a.jz(endproc);

			a.bind(loop_rt);
			a.mov(x86::edi, x86::dword_ptr(x86::rsi));		//ƫ�ƻ�ַ��ַ
			a.add(x86::rdi, x86::rax);		//��ʱ rdi Ϊ���ص��ڴ�������ַ��ַ
			//����
			a.mov(x86::ecx, x86::dword_ptr(x86::rsi, 4));
			a.sub(x86::ecx, 8);
			a.shr(x86::ecx, 1);	//��ʱΪ�ض�λ�����ʵ��Ŀ����
			a.add(x86::rsi, 8);	//��ָ��ָ��������µĵ�һ���ض�λ��Ŀ

			a.bind(loop_reloc);
			a.dec(x86::rcx);
			a.mov(x86::dx, x86::word_ptr(x86::rsi, x86::rcx, 1));
			a.test(x86::dx, 0xF000);
			a.jz(loop_reloc);		//contine;
			a.and_(x86::edx, 0xFFF);
			a.add(x86::rdx, x86::rdi);
			a.sub(x86::qword_ptr(x86::rdx), x86::r10);	//����
			a.cmp(x86::rcx, 0);
			a.ja(loop_reloc);

			a.sub(x86::rsi, 8);	//����ָ���ͷ
			a.mov(x86::edx, x86::dword_ptr(x86::rsi, 4));
			a.add(x86::rsi, x86::rdx);		//ָ����һ��
			a.mov(x86::edx, x86::dword_ptr(x86::rsi));
			a.test(x86::edx, x86::edx);
			a.jnz(loop_rt);

			a.bind(endproc);

			a.pop(x86::r10);
			a.pop(x86::rdx);
			a.pop(x86::rsi);	//�ͷ� rsi ������
			a.pop(x86::rcx);
			a.pop(x86::rdi);
		}
		else
		{
			a.push(x86::edi);
			a.push(x86::ecx);

			a.push(x86::esi);		//���� rsi
			a.mov(x86::esi, rdd.VirtualAddress);	//�ض�λ���ַ
			a.add(x86::esi, x86::eax);

			a.push(x86::edx);	//���� edx

			a.push((DWORD32)peinfo.ImageBase);	//x86�Ĵ���û��ô�ֻ࣬���Լ�ά��һ���ֲ�����
			a.sub(x86::dword_ptr(x86::esp), x86::rax);
			a.jz(endproc);

			a.bind(loop_rt);
			a.mov(x86::edi, x86::dword_ptr(x86::esi));		//ƫ�ƻ�ַ��ַ
			a.add(x86::edi, x86::eax);		//��ʱ rdi Ϊ���ص��ڴ�������ַ��ַ
			//����
			a.mov(x86::ecx, x86::dword_ptr(x86::esi, 4));
			a.sub(x86::ecx, 8);
			a.shr(x86::ecx, 1);	//��ʱΪ�ض�λ�����ʵ��Ŀ����
			a.add(x86::esi, 8);	//��ָ��ָ��������µĵ�һ���ض�λ��Ŀ

			a.bind(loop_reloc);
			a.dec(x86::ecx);
			a.mov(x86::dx, x86::word_ptr(x86::rsi, x86::ecx, 1));
			a.test(x86::dx, 0xF000);
			a.jz(loop_reloc);		//contine;
			a.and_(x86::edx, 0xFFF);
			a.add(x86::edx, x86::edi);

			a.push(x86::eax);	//ʹ�þֲ�����
			a.mov(x86::eax, x86::dword_ptr(x86::esp, 4));	//ע�ⱻ push ��һ�������ԼӸ�ƫ��
			a.sub(x86::dword_ptr(x86::edx), x86::eax);	//����
			a.pop(x86::eax);

			a.cmp(x86::ecx, 0);
			a.ja(loop_reloc);

			a.sub(x86::esi, 8);	//����ָ���ͷ
			a.mov(x86::edx, x86::dword_ptr(x86::esi, 4));
			a.add(x86::esi, x86::rdx);		//ָ����һ��
			a.mov(x86::edx, x86::dword_ptr(x86::esi));
			a.test(x86::edx, x86::edx);
			a.jnz(loop_rt);

			a.bind(endproc);

			a.add(x86::esp, 4);		//�ͷžֲ�����
			a.pop(x86::edx);
			a.pop(x86::esi);	//�ͷ� rsi ������

			a.pop(x86::ecx);
			a.pop(x86::edi);
		}

		//�����еĽ�ȫ����Ϊ��д
		auto length = peinfo.NumberOfSections;
		for (UINT i = 0; i < length; i++)
		{
			((PIMAGE_SECTION_HEADER)TranModPEWapper(&peinfo.PSectionHeaders[i]))
				->Characteristics |= IMAGE_SCN_MEM_WRITE;
		}
	}

	INT3264 CWingProtect::TranModPE(INT3264 Addr)
	{
		return OFFSET(packedPE, GETOFFSET(mapping, Addr));
	}

	void CWingProtect::CorrectWingSection()
	{
		auto wingSection = peinfo.WingSection;
		if (!wingSection) return;

		char name[] = ".wing";
		memcpy_s(wingSection->Name, 8, name, sizeof(name));

		auto totalsize = peinfo.PointerOfWingSeciton;
		auto t = div(totalsize, peinfo.FileAlignment);
		wingSection->Misc.VirtualSize = (DWORD)totalsize;
		wingSection->SizeOfRawData = (DWORD)GetBiggerQuot(t) * peinfo.FileAlignment;
		wingSection->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
			| IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
		//wingSection->VirtualAddress = peinfo.AnalysisInfo.MinAvailableVirtualAddress;		�ѱ���ʼ��
		wingSection->PointerToRawData = (DWORD)peinfo.FileSize.QuadPart;

		if (ImportTableNeedCorrent)
		{
			auto im = (PIMAGE_DATA_DIRECTORY)TranModPEWapper(&peinfo.PDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
			im->VirtualAddress = wingSection->VirtualAddress;
			im->Size = wingSection->SizeOfRawData;
		}

		auto vsize = div(totalsize, peinfo.SectionAlignment);
		*(DWORD*)TranModPEWapper(peinfo.PSizeOfImage) += (DWORD)(GetBiggerQuot(vsize) * peinfo.SectionAlignment);

		auto pnew = (PIMAGE_SECTION_HEADER)TranModPEWapper(peinfo.PSectionHeaders);
		memcpy_s(&pnew[peinfo.NumberOfSections], IMAGE_SIZEOF_SECTION_HEADER, wingSection, IMAGE_SIZEOF_SECTION_HEADER);
		++(*(WORD*)TranModPEWapper(peinfo.PNumberOfSections));

	}

	BOOL CWingProtect::ProcessTLS(BOOL Encrypt)
	{
		using namespace asmjit;

		if (!HasTLS)
			return FALSE;

		auto pdtls = peinfo.PDataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		auto rvabase = peinfo.AnalysisInfo.MinAvailableVirtualAddress;
#define AddRVABase(offset) ((UINT)offset + (UINT)rvabase)

		if (is64bit)
		{
			auto ptlsd = (PIMAGE_TLS_DIRECTORY64)GetPointerByRVA(packedPE, pdtls.VirtualAddress);
			encryptInfo.OldTLSCallBacks = (UINT)(ptlsd->AddressOfCallBacks - peinfo.ImageBase);
			auto callbacks = (UINT64*)GetPointerByRVA(packedPE, encryptInfo.OldTLSCallBacks);

			vector<UINT> rvasTLS;
			for (int i = 0; callbacks[i]; i++)
				rvasTLS.push_back(UINT(callbacks[i] - peinfo.ImageBase));

			auto pc = (UINT64*)OFFSET(peinfo.WingSecitonBuffer, peinfo.PointerOfWingSeciton);
			auto b = peinfo.PointerOfWingSeciton;
			encryptInfo.TLSBuffer = (UINT)b;
			auto length = rvasTLS.size() + 1;

			for (int i = 0; i < length; i++)
			{
				pc[i] = 0;
			}

			b += length * sizeof(UINT64);
			pc += length;

			encryptInfo.TLSBufferShadow = (UINT)b;

			if (Encrypt)
			{
				for (int i = 0; i < length - 1; i++)
				{
					pc[i] = rvasTLS[i] ^ 0x85451;
				}

				auto pp = (char*)(pc + length);
				b += length * sizeof(UINT64);
				encryptInfo.TLSDispatcher = (UINT)b;

				Environment env(Arch::kX64);
				CodeHolder holder;
				holder.init(env);
				x86::Assembler a(&holder);

				// gs:[0x60]
				x86::Mem mem;
				mem.setSegment(x86::gs);
				mem.setOffset(0x60);

				a.push(x86::rbx);
				a.mov(x86::rbx, mem);
				a.mov(x86::rbx, x86::qword_ptr(x86::rbx, 0x10));
				a.mov(x86::r10, x86::rbx);
				a.add(x86::rbx, AddRVABase(encryptInfo.TLSBufferShadow));
				a.mov(x86::rbx, x86::qword_ptr(x86::rbx, x86::eax, 3));
				a.xor_(x86::rbx, 0x85451);
				a.add(x86::rbx, x86::r10);
				a.mov(x86::rax, x86::rbx);
				a.pop(x86::rbx);
				a.pop(x86::r10);		//�Ѿ�ѹ��� r10����Ҫ�ָ�
				a.jmp(x86::rax);		//jmp to the real function addr			
				a.nop();

				vector<UINT> tlsentry;

				//���� Hook ��ַ
				for (int i = 0; i < length - 1; i++)
				{
					tlsentry.push_back((UINT)(holder.codeSize() + b));

					a.push(x86::r10);
					a.mov(x86::r10, mem);
					a.mov(x86::r10, x86::qword_ptr(x86::r10, 0x10));
					a.add(x86::r10, AddRVABase(encryptInfo.TLSDispatcher));
					a.mov(x86::eax, i);
					a.jmp(x86::r10);
					a.nop();
				}

				BYTE* shellcode = a.bufferData();
				UINT sizecode = (UINT)holder.codeSize();
				memcpy_s(pp, sizecode, shellcode, sizecode);

				for (int i = 0; i < length - 1; i++)
				{
					callbacks[i] = AddRVABase(tlsentry[i] + peinfo.ImageBase);
				}

				ptlsd->AddressOfCallBacks = AddRVABase(encryptInfo.TLSBuffer) + peinfo.ImageBase;

				peinfo.PointerOfWingSeciton += (b + sizecode);
			}
			else
			{
				auto ptlsd = (PIMAGE_TLS_DIRECTORY64)GetPointerByRVA(packedPE, pdtls.VirtualAddress);
				encryptInfo.OldTLSCallBacks = (UINT)(ptlsd->AddressOfCallBacks - peinfo.ImageBase);
				auto callbacks = (UINT64*)GetPointerByRVA(packedPE, encryptInfo.OldTLSCallBacks);
				auto pc = (UINT64*)OFFSET(peinfo.WingSecitonBuffer, peinfo.PointerOfWingSeciton);
				encryptInfo.TLSBuffer = (UINT)b;
				auto length = rvasTLS.size() + 1;

				for (int i = 0; i < length; i++)
				{
					pc[i] = 0;
				}

				b += length * sizeof(UINT64);
				ptlsd->AddressOfCallBacks = AddRVABase(encryptInfo.TLSBuffer) + peinfo.ImageBase;

				for (int i = 0; i < length - 1; i++)
				{
					callbacks[i] -= peinfo.ImageBase;		//תΪ RVA
				}
			}

			//�����µ��ض�λĿ¼����Ϊ TLS ��ʼ�����ڳ���ִ��
			auto dr = (PIMAGE_DATA_DIRECTORY)TranModPEWapper(
				&peinfo.PDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

			//�����ļ�����
			auto t = div(b, peinfo.FileAlignment);
			auto e = GetBiggerQuot(t) * peinfo.FileAlignment;
			b = e;

			dr->VirtualAddress = AddRVABase(b);

			auto pdr = (PIMAGE_BASE_RELOCATION)OFFSET(pc, b);

			auto raddr = ptlsd->AddressOfCallBacks;
			auto rvaa = raddr - peinfo.ImageBase;
			pdr->VirtualAddress = rvaa & ~0xFFF;
			pdr->SizeOfBlock = 0x10;

			dr->Size = pdr->SizeOfBlock + sizeof(IMAGE_BASE_RELOCATION) * 2;
			auto ri = (WORD*)OFFSET(pdr, sizeof(IMAGE_BASE_RELOCATION));
			memset(ri, 0, 0x8);
			*ri = rvaa & 0xFFF | (IMAGE_REL_BASED_DIR64 << 12);

			b += dr->Size;

			peinfo.PointerOfWingSeciton += b;
		}
		else
		{
			auto ptlsd = (PIMAGE_TLS_DIRECTORY32)GetPointerByRVA(packedPE, pdtls.VirtualAddress);
			encryptInfo.OldTLSCallBacks = (UINT)(ptlsd->AddressOfCallBacks - peinfo.ImageBase);
			auto callbacks = (UINT32*)GetPointerByRVA(packedPE, ptlsd->AddressOfCallBacks - peinfo.ImageBase);

			vector<UINT> rvasTLS;
			for (int i = 0; callbacks[i]; i++)
				rvasTLS.push_back(UINT(callbacks[i] - peinfo.ImageBase));

			auto pc = (UINT*)OFFSET(peinfo.WingSecitonBuffer, peinfo.PointerOfWingSeciton);
			auto b = peinfo.PointerOfWingSeciton;
			encryptInfo.TLSBuffer = (UINT)b;

			auto length = rvasTLS.size();

			if (Encrypt)
			{
				for (int i = 0; i < length; i++)
				{
					pc[i] = rvasTLS[i] ^ 0x85451;
				}

				auto pp = (char*)OFFSET(pc, length * sizeof(UINT));
				b += length * sizeof(UINT);
				encryptInfo.TLSDispatcher = (UINT)b;

				Environment env(Arch::kX86);
				CodeHolder holder;
				holder.init(env);
				x86::Assembler a(&holder);

				// fs:[0x30]
				x86::Mem mem;
				mem.setSegment(x86::fs);
				mem.setOffset(0x30);

				a.push(x86::edi);
				a.push(x86::esi);
				a.push(x86::ebx);
				a.push(x86::ecx);
				a.mov(x86::ebx, mem);
				a.mov(x86::ebx, x86::dword_ptr(x86::ebx, 0x8));
				a.mov(x86::ecx, x86::ebx);
				a.add(x86::ebx, AddRVABase(encryptInfo.TLSBufferShadow));
				a.mov(x86::ebx, x86::dword_ptr(x86::ebx, x86::eax, 2));
				a.xor_(x86::ebx, 0x85451);
				a.add(x86::ebx, x86::ecx);

				a.sub(x86::esp, 12);
				a.mov(x86::esi, x86::edx);
				a.mov(x86::edi, x86::esp);
				a.mov(x86::ecx, 3);
				a.rep();
				a.movsd();
				a.call(x86::ebx);		//call the real function

				a.pop(x86::ecx);
				a.pop(x86::ebx);
				a.pop(x86::esi);
				a.pop(x86::edi);
				
				a.ret(0xC);
				a.nop();

				vector<UINT> tlsentry;

				//���� Hook ��ַ
				for (int i = 0; i < length; i++)
				{
					tlsentry.push_back((UINT)(holder.codeSize() + b));

					a.push(x86::edx);
					a.mov(x86::edx, x86::esp);
					a.add(x86::edx, 8);		//����ָ��
					a.push(x86::ecx);
					a.mov(x86::ecx, mem);
					a.mov(x86::ecx, x86::dword_ptr(x86::ecx, 0x8));
					a.add(x86::ecx, AddRVABase(encryptInfo.TLSDispatcher));
					a.mov(x86::eax, i);		
					a.call(x86::ecx);
					a.pop(x86::ecx);
					a.pop(x86::edx);
					a.ret();
					a.nop();
				}

				BYTE* shellcode = a.bufferData();
				UINT sizecode = (UINT)holder.codeSize();
				memcpy_s(pp, sizecode, shellcode, sizecode);

				for (int i = 0; i < length; i++)
				{
					callbacks[i] = (UINT)AddRVABase(tlsentry[i] + peinfo.ImageBase);
				}

				peinfo.PointerOfWingSeciton += (b + sizecode);
			}
			else
			{
				auto ptlsd = (PIMAGE_TLS_DIRECTORY64)GetPointerByRVA(packedPE, pdtls.VirtualAddress);
				encryptInfo.OldTLSCallBacks = (UINT)(ptlsd->AddressOfCallBacks - peinfo.ImageBase);
				auto callbacks = (UINT*)GetPointerByRVA(packedPE, encryptInfo.OldTLSCallBacks);
				auto pc = (UINT*)OFFSET(peinfo.WingSecitonBuffer, peinfo.PointerOfWingSeciton);
				encryptInfo.TLSBuffer = (UINT)b;
				auto length = rvasTLS.size() + 1;

				for (int i = 0; i < length; i++)
				{
					pc[i] = 0;
				}

				b += length * sizeof(UINT);
				ptlsd->AddressOfCallBacks = AddRVABase(encryptInfo.TLSBuffer) + peinfo.ImageBase;

				for (int i = 0; i < length - 1; i++)
				{
					callbacks[i] = (UINT)peinfo.ImageBase;		//תΪ RVA
				}
			}

			//�����µ��ض�λĿ¼����Ϊ TLS ��ʼ�����ڳ���ִ��
			auto dr = (PIMAGE_DATA_DIRECTORY)TranModPEWapper(
				&peinfo.PDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

			//�����ļ�����
			auto t = div(b, peinfo.FileAlignment);
			auto e = GetBiggerQuot(t) * peinfo.FileAlignment;
			b = e;

			dr->VirtualAddress = AddRVABase(b);

			auto pdr = (PIMAGE_BASE_RELOCATION)OFFSET(pc, b);

			auto raddr = ptlsd->AddressOfCallBacks;
			auto rvaa = raddr - peinfo.ImageBase;
			pdr->VirtualAddress = rvaa & ~0xFFF;
			pdr->SizeOfBlock = 0x10;

			dr->Size = pdr->SizeOfBlock + sizeof(IMAGE_BASE_RELOCATION) * 2;
			auto ri = (WORD*)OFFSET(pdr, sizeof(IMAGE_BASE_RELOCATION));
			memset(ri, 0, 0x8);
			*ri = rvaa & 0xFFF | (IMAGE_REL_BASED_DIR64 << 12);

			b += dr->Size;

			peinfo.PointerOfWingSeciton += b;
		}

		return TRUE;
	}

	BOOL CWingProtect::Save2File(const TCHAR* filename)
	{
		HANDLE file = CreateFile(filename, FILE_ALL_ACCESS, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE)
			return FALSE;

		CorrectWingSection();

		assert(encryptInfo.ShellCodeLoader);

		*(DWORD*)TranModPEWapper(peinfo.PAddressOfEntryPoint) = 
			peinfo.WingSection->VirtualAddress + encryptInfo.ShellCodeLoader;	//�޸� OEP

		auto ret = WriteFile(file, packedPE, (DWORD)peinfo.FileSize.QuadPart, NULL, NULL);
		ret &= WriteFile(file, peinfo.WingSecitonBuffer, (DWORD)peinfo.WingSection->SizeOfRawData, NULL, NULL);

		CloseHandle(file);
		return ret;
	}

	void CWingProtect::DestoryRelocation()
	{
		//�ݻ��ض�λ����ֹ�����������ǽ��д�����޸�			
		auto l = (PIMAGE_DATA_DIRECTORY)TranModPEWapper(&peinfo.PDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
		l->VirtualAddress = 0;
		l->Size = 0;
	}

	BOOL CWingProtect::ProtectionsHasFlag(UINT protections, Protections flag)
	{
		return protections & (UINT)flag ? TRUE : FALSE;
	}

	INT3264 CWingProtect::RVA2FOA(INT3264 rva)
	{
		if (_lasterror != ParserError::LoadingFile)
		{
			if (_lasterror != ParserError::Success || rva > peinfo.SizeOfImage)
			{
				return INVALID_ADDR;
			}
		}

		if (peinfo.FileAlignment == 0 || peinfo.SectionAlignment == 0)
		{
			return INVALID_ADDR;
		}

		if (peinfo.SizeOfHeaders)
		{
			if (rva <= peinfo.SizeOfHeaders)
			{
				return rva;
			}
			else
			{
				auto it = (PIMAGE_SECTION_HEADER)peinfo.PSectionHeaders;
				if (it->VirtualAddress > rva)
				{
					return rva;
				}
				for (UINT i = 0; i < peinfo.NumberOfSections; i++)
				{
					if (rva >= it->VirtualAddress &&
						rva <= (INT3264)(it->VirtualAddress) + it->SizeOfRawData)
					{
						return it->PointerToRawData + rva - it->VirtualAddress;
					}
					if (i != peinfo.NumberOfSections - 1)
					{
						it++;
						if (rva < it->VirtualAddress)
						{
							return it->PointerToRawData + rva - it->VirtualAddress;
						}
					}
					else
					{
						if (rva > (INT3264)(it->VirtualAddress) + it->SizeOfRawData)
						{
							return it->PointerToRawData + rva - it->VirtualAddress;
						}
					}
				}
			}
		}
		return INVALID_ADDR;
	}

	INT3264 CWingProtect::FOA2RVA(INT3264 foa)
	{
		if (_lasterror != ParserError::LoadingFile)
		{
			if (_lasterror != ParserError::Success || foa > peinfo.FileSize.QuadPart)
			{
				return INVALID_ADDR;
			}
		}

		if (peinfo.SectionAlignment == 0 || peinfo.FileAlignment == 0)
		{
			return INVALID_ADDR;
		}
		if (peinfo.SizeOfHeaders)
		{
			if (foa <= peinfo.SizeOfHeaders)
			{
				return foa;
			}
			else
			{
				auto it = (PIMAGE_SECTION_HEADER)peinfo.PSectionHeaders;
				if (it->PointerToRawData > foa)
				{
					return foa;
				}
				for (UINT i = 1; i < peinfo.NumberOfSections; i++)
				{
					if (foa >= it->PointerToRawData &&
						foa <= (INT3264)(it->PointerToRawData) + it->SizeOfRawData)
					{
						return it->VirtualAddress + foa - it->PointerToRawData;
					}
					if (i != peinfo.NumberOfSections - 1)
					{
						it++;
						if (foa < it->PointerToRawData)
						{
							return it->VirtualAddress + foa - it->PointerToRawData;
						}
					}
					else
					{
						if (foa > (INT3264)(it->PointerToRawData) + it->SizeOfRawData)
						{
							return it->VirtualAddress + foa - it->PointerToRawData;
						}
					}
				}
			}
		}
		return INVALID_ADDR;
	}

}