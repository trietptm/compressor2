// EXE-compressor.cpp
#include "stdafx.h"
#include "Windows.h"
#include "Dbghelp.h"
#include "conio.h"
#include "aplib.h"
#pragma comment(lib,"aplib.lib")
//Глобальные переменные
HANDLE hEXE,hNew_exe,hTime;
HANDLE hEXEmap,hNEWmap;
PIMAGE_NT_HEADERS pNTh_n;
LONG dos_e_lfanew;
char *pUnpacker_code;
DWORD unpacker_code_size;
LPVOID pBuf_exe,pBuf_exe_start,pBuf_new,pBuf_new_start;
WORD NumberOfSections;
WORD import_table_size=0x60;//размер таблицы импорта, помещаемой в началеk 
DWORD lsize;//младшее двойнное слово размера файла(в байтах).
DWORD image_base;
DWORD oep;//адрес точки входа
DWORD oep_import;//адрес таблицы импорта 
DWORD old_size;//старый размер файла
DWORD import_size;//размер исходной таблицы импорта
DWORD new_size;//новый размер файла
DWORD file_align;
PIMAGE_SECTION_HEADER pSecth_comp;//секция упаковщика

DWORD rLoadLibrary = 0;
DWORD rGetProcAddress = 0;
//Константы
const char *Kernel = "Kernel32.dll";
const char *Load_Library = "LoadLibraryA";
const char *Get_Proc_Address = "GetProcAddress";

const char	*szKernel32		= "Kernel32.dll";
DWORD		dwKernelBase		= 0;
const char	*szGetModuleHandle	= "GetModuleHandleA";
DWORD		rGetModuleHandle	= 0;
const char	*szVirtualAlloc		= "VirtualAlloc";
DWORD		rVirtualAlloc		= 0;
const char	*szVirtualFree		= "VirtualFree";
DWORD		rVirtualFree		= 0;
const char	*szExitProcess		= "ExitProcess";
DWORD		rExitProcess		= 0;
const char	*szUser32		= "User32.dll";
DWORD		dwUserBase		= 0;
const char	*szMessageBox		= "MessageBoxA";
DWORD		rMessageBox		= 0;
//Функции
void pack_exe();//создание упакованного файла
void depack_exe(_TCHAR *name_new_exe);//получить исходный файл
bool valid_file();//проверка файла на валидность
void changes_of_sections(PIMAGE_NT_HEADERS pNTh);//работа с секциями
void copy_section(DWORD psource,DWORD preceiver,DWORD size);//копирование секции
DWORD pack_section(DWORD psource,DWORD preceiver,DWORD size);//сжимание секции
void loader();//загрузчик
void create_new_import_table(LPVOID base,DWORD row_data,DWORD virt_addr);//создаем таблицу импорта
PIMAGE_SECTION_HEADER rva_to_section(PIMAGE_FILE_HEADER pFh, DWORD RVA);//возвращает описание секции
DWORD get_func_rva(void* func_name);//получение RVA функции(загрузчика)
DWORD get_func_size(void* func_name);//получение размера функции(загрузчика)
char* copy_func(void* func_name);//копирует тело функции(загрузчика) в буфер
void init_loader_variables(char* pUnpack_code);//инициализируем переменные загрузчика
DWORD align(DWORD value,DWORD align);//функция для выравнивания адресов
bool file_is_pack();//проверка на упакованность

int _tmain(int argc, _TCHAR* argv[])
{
	_TCHAR *name_exe,*name_new_exe,*mode;
	if(argc!=4)
	{
		printf("Wrong number of parametres!");
		_getch();
		return 0;
	}
	if(argv[1] && (wcscmp(argv[1],__TEXT("d"))==0 || wcscmp(argv[1],__TEXT("c"))==0
	           || wcscmp(argv[1],__TEXT("D"))==0 || wcscmp(argv[1],__TEXT("C"))==0))
		mode=argv[1];
	else {
		printf("Wrong mode!");
		_getch();
		return 0;
	}
	if(argv[2])
		name_exe=argv[2];
	else {
		printf("File name is not found!");
		_getch();
		return 0;
	}
	if(argv[3])
		name_new_exe=argv[3];
	else {
		printf("Wrong output file!");
		_getch();
		return 0;
	}
	hEXE=CreateFile(name_exe,GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		0,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,0);
	if(hEXE==INVALID_HANDLE_VALUE)
	{
		printf("File is not found!");
		_getch();
		return 0;
	}
	hEXEmap=CreateFileMapping(hEXE, 0, PAGE_READWRITE, 0, 0, 0);
	pBuf_exe_start=pBuf_exe=MapViewOfFile(hEXEmap,FILE_MAP_ALL_ACCESS,0,0,0);
	if(valid_file()==false)
	{
		printf("This file is not executed!");
		UnmapViewOfFile(pBuf_exe);
		CloseHandle(hEXEmap);
		CloseHandle(hEXE);
		_getch();
		return 0;
	}
	//Упаковка
	if(wcscmp(mode,__TEXT("c"))==0 || wcscmp(mode,__TEXT("C"))==0)
	{
		if(file_is_pack()==true)
		{
			printf("The file is already packed!");
			UnmapViewOfFile(pBuf_exe);
			CloseHandle(hEXEmap);
			CloseHandle(hEXE);
			_getch();
			return 0;
		}
		printf("Working...\n");
		hNew_exe=CreateFile(name_new_exe,GENERIC_READ | GENERIC_WRITE, 
			FILE_SHARE_READ | FILE_SHARE_WRITE,0,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,0);
		unpacker_code_size=get_func_size(loader);//получаем размер загрузчика
		pUnpacker_code=new char[unpacker_code_size];//выделяем буфер под код загрузчика
		pUnpacker_code=copy_func(loader);//указатель на буфер с кодом загрузчика
		lsize=GetFileSize(hEXE,NULL);//получаем размер исходного файла
		old_size=lsize;
		hTime=hNew_exe;
		//перемещае указатель на размер файла
		SetFilePointer(hTime, old_size+unpacker_code_size+import_table_size,NULL,FILE_BEGIN);
		SetEndOfFile(hTime);//размер файла увеличивается до указанной величины
		hNEWmap=CreateFileMapping(hNew_exe, 0, PAGE_READWRITE, 0, 0, 0);
		pBuf_new_start=pBuf_new=MapViewOfFile(hNEWmap,FILE_MAP_ALL_ACCESS,0,0,0);

		pack_exe();
		printf("Packing is finished successfully!!!");
	}
	//Распаковка
	if(wcscmp(mode,__TEXT("d"))==0 || wcscmp(mode,__TEXT("D"))==0)
	{
		if(file_is_pack()==false)
		{
			printf("The file is not packed!");
			UnmapViewOfFile(pBuf_exe);
			CloseHandle(hEXEmap);
			CloseHandle(hEXE);
			_getch();
			return 0;
		}
		printf("Working...\n");
		hNew_exe=CreateFile(name_new_exe,GENERIC_READ | GENERIC_WRITE, 
			FILE_SHARE_READ | FILE_SHARE_WRITE,0,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,0);
		depack_exe(name_new_exe);
		printf("Unpacking is finished successfully!!!");
	}
	//Закрываем все handle и уничтожаем отображения
	UnmapViewOfFile(pBuf_exe);
	UnmapViewOfFile(pBuf_new);
	CloseHandle(hEXEmap);
	CloseHandle(hEXE);
	CloseHandle(hNEWmap);
	//Устанавливаем новый размер файле
	SetFilePointer(hNew_exe,new_size,NULL,FILE_BEGIN);
	SetEndOfFile(hTime);//размер файла увеличивается до указанной величины
	CloseHandle(hNew_exe);
	_getch();
	return 1;
}
bool valid_file()
{
	PIMAGE_DOS_HEADER pDosh;
	PIMAGE_NT_HEADERS pNTh;
	pDosh=(PIMAGE_DOS_HEADER)pBuf_exe;
	if(pDosh->e_magic!=IMAGE_DOS_SIGNATURE)
		return false;
	pNTh=(PIMAGE_NT_HEADERS)(LPVOID)((int)pBuf_exe+pDosh->e_lfanew);
	if(pNTh->Signature!=IMAGE_NT_SIGNATURE)
		return false;
	if(pNTh->FileHeader.Characteristics==IMAGE_FILE_DLL)
	{
		printf("Excuse, packing dll is not supported!\n");
		return false;
	}
	return true;
}
void pack_exe()
{
	PIMAGE_DOS_HEADER pDosh;
	PIMAGE_NT_HEADERS pNTh;
	/*
	  Создаем новый исполняемый файл
	  Загрузчик будет создан в отдельной секции
	*/
	pDosh=(PIMAGE_DOS_HEADER)pBuf_exe;//считываем dos-заголовок
	//копируем в новый файл dos-заголовок без изменений
	MoveMemory(pBuf_new,pBuf_exe,pDosh->e_lfanew);
	//перемещаем указатель на начало PE-заголовка в обоих файлах (pDosh->e_lfanew - адрес начала PE-заголовок)
	pBuf_exe=(LPVOID)((int)pBuf_exe+pDosh->e_lfanew	);
	pBuf_new=(LPVOID)((int)pBuf_new+pDosh->e_lfanew	);
	dos_e_lfanew=pDosh->e_lfanew;
	pNTh=(PIMAGE_NT_HEADERS)pBuf_exe;	//считываем PE-заголовок
	MoveMemory(pBuf_new,&(pNTh->Signature),sizeof(pNTh->Signature));//записываем сигнатуру
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->Signature));//смещаемся в новом файле
	MoveMemory(pBuf_new,&(pNTh->FileHeader.Machine),sizeof(pNTh->FileHeader.Machine));//записываем платформу
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->FileHeader.Machine));
	NumberOfSections=pNTh->FileHeader.NumberOfSections+1;//увеличиваем кол-во секции на 1 (для загрузчика)
	MoveMemory(pBuf_new,&(NumberOfSections),sizeof(pNTh->FileHeader.NumberOfSections));//количесто секций
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->FileHeader.NumberOfSections));
	//Поля TimeDateStamp, PointerToSymbolTable, NumberOfSymbols нас не интересуют
	//Поэтому пропустим их и перейдем к полю SizeOfOptionalHeader
	pBuf_new=(LPVOID)((int)pBuf_new+12);
	MoveMemory(pBuf_new,&(pNTh->FileHeader.SizeOfOptionalHeader),sizeof(pNTh->FileHeader.SizeOfOptionalHeader));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->FileHeader.SizeOfOptionalHeader));
	MoveMemory(pBuf_new,&(pNTh->FileHeader.Characteristics),sizeof(pNTh->FileHeader.Characteristics));//характеристики
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->FileHeader.Characteristics));
	//Далее переносим все поля опционального заголовка неизменными
	//Возможно, в дальнейшем некоторые из них будут модифицироваться
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader),0xE0);
	image_base=pNTh->OptionalHeader.ImageBase;//базовый адрес
	oep=pNTh->OptionalHeader.AddressOfEntryPoint;//базовая точка входа
	file_align=pNTh->OptionalHeader.FileAlignment;
	pBuf_new=(LPVOID)((int)pBuf_new+0xE0);
	//С PE-заголовком пока все
	//Переходим к обработке секций
	changes_of_sections(pNTh);
}
void changes_of_sections(PIMAGE_NT_HEADERS pNTh)
{
	DWORD delta=0;//смещение секции в файле
	DWORD rva_tls_section=0;//RVA секции TLS
	DWORD rva_reloc_section=0;//RVA секции релоков
	DWORD rva_rsrc_section=0;//RVA секции ресурсов
	DWORD size_of_image=0;//новое значение размера образа
	DWORD new_size_sect;
	DWORD old_hd_size;//старый размер заголовков
	DWORD align_VS,align_RS;//выравненный виртуальный размер страницы
	int offset;//смещение в структуре IMAGE_SECTION_HEADER
	DWORD pRawData_exe,pRawData_new;//физ. смещения секций
	BYTE flag=1;//разрешение упаковки(0-нет,1-да)
	char name[5]={'.','c','o','m','p'};//имя новой секции
	DWORD EntryPoint;
	DWORD ImportVA;
	DWORD buf;
	DWORD wbuf;
	LPVOID pBuf_new_FS=pBuf_new;//сохраним адрес первой секции в новом файле
	LPVOID pBuf_exe_FS;//адрес первой секции в исходном
	int i;
	PIMAGE_SECTION_HEADER pSecth,pSecth_new;
	//Получаем RVA таблицы импорта
	oep_import=pNTh->OptionalHeader.DataDirectory[1].VirtualAddress;
	import_size=pNTh->OptionalHeader.DataDirectory[1].Size;
	//Получаем RVA секции ресурсов
	pSecth=rva_to_section(&(pNTh->FileHeader),pNTh->OptionalHeader.DataDirectory[2].VirtualAddress);
	if(pSecth!=NULL)
		rva_rsrc_section=pSecth->VirtualAddress;
	//Получаем RVA секции TLS
	pSecth=rva_to_section(&(pNTh->FileHeader),pNTh->OptionalHeader.DataDirectory[9].VirtualAddress);
	if(pSecth!=NULL)
		rva_tls_section=pSecth->VirtualAddress;
	//Получаем RVA секции релоков
	pSecth=rva_to_section(&(pNTh->FileHeader),pNTh->OptionalHeader.DataDirectory[5].VirtualAddress);
	if(pSecth!=NULL)
		rva_reloc_section=pSecth->VirtualAddress;
	//После перезаписи в новый файл опционального заголовка, pBuf_new указывает на начало первой секции
	//Переместим указатель исходного exe также на начало первой секции
	pBuf_exe=pBuf_exe_FS=(LPVOID)((DWORD)(&(pNTh->FileHeader) + 1) + pNTh->FileHeader.SizeOfOptionalHeader);
	pSecth=(PIMAGE_SECTION_HEADER)pBuf_exe;
	old_hd_size=pNTh->OptionalHeader.SizeOfHeaders;//сохраняем старый размер заголовков
	//Далее проходим по всем секциям и производим требуемые преобразования
	for(i=0;i<pNTh->FileHeader.NumberOfSections;i++)
	{
		//Имя секции переписываем без изменений
		offset=0;
		MoveMemory((LPVOID)((int)pBuf_new+offset),&(pSecth->Name),sizeof(pSecth->Name));
		//Выравниваем виртуальные размеры секций
		align_VS=align(pSecth->Misc.VirtualSize,0x1000);
		offset=sizeof(pSecth->Name);
		MoveMemory((LPVOID)((int)pBuf_new+offset),&(align_VS),sizeof(align_VS));
		size_of_image+=align_VS;//подсчитываем новый размер образа
		offset+=sizeof(pSecth->Misc);
		//Виртуальный адрес переписываем без изменений
		MoveMemory((LPVOID)((int)pBuf_new+offset),&(pSecth->VirtualAddress),sizeof(pSecth->VirtualAddress));
		offset+=sizeof(pSecth->VirtualAddress);
		//Физический размер переписываем без изменений
		MoveMemory((LPVOID)((int)pBuf_new+offset),&(pSecth->SizeOfRawData),sizeof(pSecth->SizeOfRawData));
		buf=pSecth->PointerToRawData;
		if(buf!=0)//возможно некоторые секции, стоящие перед данной, удалялись
			buf-=delta;//вводим поправку в физический адрес
		offset+=sizeof(pSecth->SizeOfRawData);
		MoveMemory((LPVOID)((int)pBuf_new+offset),&(buf),sizeof(buf));
		//Устанавливаем атрибуты чтения и записи секции
		offset+=16;//смещаемся на поле Characteristics
		buf=pSecth->Characteristics;//считываем исходные флаги
		buf=buf|(IMAGE_SCN_MEM_READ+IMAGE_SCN_MEM_WRITE);//разрешаем чтение запись
		buf=buf&(~IMAGE_SCN_MEM_SHARED);//запрещаем общедоступность
		MoveMemory((LPVOID)((int)pBuf_new+offset),&(buf),sizeof(buf));
		++pSecth;//следующая секция в исходном файле
		pBuf_new=(LPVOID)((int)pBuf_new+sizeof(IMAGE_SECTION_HEADER));// и в новом файле
	}
	//Задаем параметры секции содержащей загрузчик
	MoveMemory((LPVOID)((int)pBuf_new),name,5);//указываем имя .comp
	offset=sizeof(pSecth->Name);
	//Виртуальный размер(физический, смещенный на file_align)
	align_VS=align(unpacker_code_size+import_table_size,file_align);
	MoveMemory((LPVOID)((int)pBuf_new+offset),&(align_VS),sizeof(align_VS));
	offset+=sizeof(pSecth->Misc)+sizeof(pSecth->VirtualAddress);
	//Физический размер секции равен размеру загрузчика
	buf=unpacker_code_size+import_table_size;
	MoveMemory((LPVOID)((int)pBuf_new+offset),&(buf),sizeof(buf));
	size_of_image+=align_VS;//увеличиваем размер образа
	offset+=sizeof(pSecth->SizeOfRawData);
	//Вычисляем физическое смещение в файле новой секции
	//Путем суммирования смещения предыдущей секции и её выравненого размера
	pSecth=(PIMAGE_SECTION_HEADER)(LPVOID)((int)pBuf_new-sizeof(IMAGE_SECTION_HEADER));
	buf=align(pSecth->SizeOfRawData,file_align);
	buf+=pSecth->PointerToRawData;
	MoveMemory((LPVOID)((int)pBuf_new+offset),&(buf),sizeof(buf));
	offset=offset-sizeof(pSecth->SizeOfRawData)-sizeof(pSecth->VirtualAddress);
	//Аналогично вычисляем виртуальный адрес новой секции
	buf=pSecth->VirtualAddress+pSecth->Misc.VirtualSize;
	ImportVA=buf;
	EntryPoint=buf+import_table_size;
	MoveMemory((LPVOID)((int)pBuf_new+offset),&(buf),sizeof(buf));
	//Устанавливаем атрибуты чтения и записи секции
	buf=IMAGE_SCN_MEM_READ+IMAGE_SCN_MEM_WRITE;
	offset+=24;//смещаемся на поле Characteristics
	MoveMemory((LPVOID)((int)pBuf_new+offset),&(buf),sizeof(buf));
	//точка входа (EntryPoint) в файле должна указывать на секцию загрузчика
	pBuf_new=pBuf_new_FS;//вернемся к адресу первой секции
	//Переместимся к полю AddressOfEntryPoint
	pBuf_new=(LPVOID)((int)pBuf_new-sizeof(pNTh->OptionalHeader)+16);
	MoveMemory((LPVOID)((int)pBuf_new),&(EntryPoint),sizeof(EntryPoint));
	//Определяем новое значение поля SizeOfHeaders
	buf=align((int)pBuf_new_FS+NumberOfSections*sizeof(IMAGE_SECTION_HEADER)-(int)pBuf_new_start,file_align);
	//Переместимся к полю SizeOfHeaders
	pBuf_new=(LPVOID)((int)pBuf_new+44);
	MoveMemory((LPVOID)((int)pBuf_new),&(buf),sizeof(buf));
	//Определим новое значение образа(размер заголовков + размер секции)
	//buf=align(buf,0x1000);
	size_of_image+=align(buf,0x1000);
	pBuf_new=(LPVOID)((int)pBuf_new-4);
	MoveMemory((LPVOID)((int)pBuf_new),&(size_of_image),sizeof(size_of_image));
	//Поскольку размер заголовков мог измениться, то вычислим смещение
	delta=buf-old_hd_size;
	//Возвращаем указатели на начало первых секций
	pBuf_exe=pBuf_exe_FS;
	pBuf_new=pBuf_new_FS;
	offset=sizeof(pSecth->Name)+12;
	/*
	Далее произведем упаковку секций при помощи библиотеки aPLib
	*/
	for(i=0;i<pNTh->FileHeader.NumberOfSections;i++)
	{
		flag=1;
		pSecth=(PIMAGE_SECTION_HEADER)pBuf_exe;
		pSecth_new=(PIMAGE_SECTION_HEADER)pBuf_new;
		//Вычисляем реальное местоположение секции в файле(с учетом адреса проецирования)
		pRawData_exe=pSecth->PointerToRawData+(int)pBuf_exe_start;
		//Изменим физичекое смещение с учетом поправки
		if(pSecth_new->PointerToRawData!=0)
			pRawData_new=pSecth_new->PointerToRawData+delta;
		else
			pRawData_new=0;
		MoveMemory((LPVOID)((int)pBuf_new+offset),&(pRawData_new),sizeof(pRawData_new));
		pRawData_new+=(int)pBuf_new_start;
		if(rva_tls_section==pSecth_new->VirtualAddress)//если это секция TLS
		{
			copy_section(pRawData_exe,pRawData_new,pSecth->SizeOfRawData);//сжимать не будем(просто копируем)
			flag=0;
		}
		if(rva_rsrc_section==pSecth_new->VirtualAddress)//если это секция ресурсов
		{	
			copy_section(pRawData_exe,pRawData_new,pSecth->SizeOfRawData);//сжимать не будем(просто копируем)
			flag=0;
		}
		if(flag==1)
		{
			new_size_sect=pack_section(pRawData_exe,pRawData_new,pSecth->SizeOfRawData);//сжимаем секцию
			if(new_size_sect==APLIB_ERROR)
				printf("Pack error!");
			align_RS=align(new_size_sect,file_align);
			MoveMemory((LPVOID)((int)pBuf_new+offset-sizeof(pSecth->SizeOfRawData)),&(align_RS),sizeof(align_RS));
			buf=pSecth->SizeOfRawData-align_RS;
			align_RS=align(buf,file_align);
			delta=delta-align_RS;
			wbuf=0xff;//флаг упаковки
			if(new_size_sect!=0)
				MoveMemory((LPVOID)((int)pBuf_new+offset+14),&(wbuf),sizeof(wbuf));
		}
		pBuf_exe=(LPVOID)((int)pBuf_exe+sizeof(IMAGE_SECTION_HEADER));
		pBuf_new=(LPVOID)((int)pBuf_new+sizeof(IMAGE_SECTION_HEADER));
	}
	//Изменим физичекое смещение с учетом поправки для новой секции
	pSecth_new=(PIMAGE_SECTION_HEADER)pBuf_new;
	pRawData_new=pSecth_new->PointerToRawData+delta;
	MoveMemory((LPVOID)((int)pBuf_new+offset),&(pRawData_new),sizeof(pRawData_new));
	new_size=pRawData_new+pSecth_new->SizeOfRawData;//новый(сжатый)размер файла
	//Создаем таблицу импорта для функционирования загрузчика
	create_new_import_table(pBuf_new_start,pRawData_new,pSecth_new->VirtualAddress);
	//Указываем новый адрес таблицы импорта
	pBuf_new=(LPVOID)((int)pBuf_new_start+dos_e_lfanew);
	pNTh_n=(PIMAGE_NT_HEADERS)pBuf_new;
	pNTh_n->OptionalHeader.DataDirectory[1].VirtualAddress=ImportVA;
	pNTh_n->OptionalHeader.DataDirectory[1].Size=import_table_size;
	MoveMemory((LPVOID)((int)pBuf_new),pNTh_n,sizeof(_IMAGE_NT_HEADERS));
	//Добавляем в файл код загрузчика
	LPVOID pAddress_IT=(LPVOID)((int)pBuf_new_start+(int)pRawData_new+import_table_size);
	init_loader_variables(pUnpacker_code);
	MoveMemory(pAddress_IT,pUnpacker_code,unpacker_code_size);
}
void copy_section(DWORD psource,DWORD preceiver,DWORD size)
{
	LPVOID s=(LPVOID)psource,r=(LPVOID)preceiver;
	MoveMemory(r,s,size);
}
DWORD pack_section(DWORD psource,DWORD preceiver,DWORD size)
{
	size_t s;
	LPVOID buf;
	DWORD new_size;
	s=aP_workmem_size(size);
	buf=VirtualAlloc(0,s,MEM_COMMIT,PAGE_READWRITE);
	new_size=aP_pack((const void*)psource,(LPVOID)preceiver,size,buf,0,0);
	VirtualFree(buf,s,MEM_DECOMMIT);
	return new_size;
}
void loader()
{
	/*
	  Функция загрузчика, внедряемая в exe.
	  Загрузка происходит в несколько этапов:
	  1) Сначала получаем адреса необходимых для загрузика функций
	     (вместе с загрузчиком встраивается небольшая таблица импорта, 
		 в которой уже есть адреса двух функций LoadLibrary и GetProcAddress).
	  2) Запускается цикл по секциям, и для секций, которые упаковывались, выделяется буфер.
	     В этот буфер скидывается упакованая секция, и производится ей распаковка по 
		 необходимому виртуальному адресу.
	  3) Считываем адрес старой таблицы импорта и загружаем все библиотеки и функции
	     необходимые для функционирования исходного файла.
	  4) Прыгаем на старую точку входа. Все.
	*/
	_asm
	{
	CALL Base
Base:
	POP EBP
	SUB EBP,OFFSET Base    //в EPB адресначала кода загрузчика
//Получаем базовые API адреса
	MOV EDX,EBP            //смещение загрузки
	ADD EDX,OFFSET dw_Image_Base//переходим на метку dw_Image_Base
	MOV EAX,DWORD PTR [EDX]//получаем значение Image_Base
	ADD EAX,[EAX+03Ch]     //смещаемся на адрес PE-заголовка
	ADD EAX,080h	       //на адрес директории импорта
	MOV ECX,DWORD PTR [EAX]//в ecx виртуальный адрес таблицы импорта
	ADD ECX,DWORD PTR [EDX]//реальный адрес
	ADD ECX,010h           //в ecx указатель на поле FirstThunk
	MOV EAX,DWORD PTR [ECX]//считываем значение этого поля
	ADD EAX,DWORD PTR [EDX]//смещаемся по этому указателю
	MOV EBX,DWORD PTR [EAX]//считываем адреса функции!
	MOV EDX,EBP            //смещение загрузки
	ADD EDX,OFFSET r_LoadLibrary//в edx адрес поля r_Load_Library
	MOV [EDX],EBX	       //запоминаем адрес функции LoadLibraryA
	ADD EAX,04h            //переходим к следующей функции
	MOV EBX,DWORD PTR [EAX]//считываем адреса функции!
	MOV EDX,EBP            //смещение загрузки
	ADD EDX,OFFSET r_GetProcAddress//в edx адрес поля r_GetProcAddress
	MOV DWORD PTR [EDX],EBX//запоминаем адрес функции GetProcAddress
//Получаем остальные адреса
	//User
	MOV EDX,EBP
	ADD EDX,OFFSET r_szUser32
	LEA EAX,[EDX]
	PUSH EAX
	MOV EDX,EBP
	ADD EDX,OFFSET r_LoadLibrary
	CALL [EDX]
	MOV EDX,EBP
	ADD EDX,OFFSET r_UserBase
	MOV ESI,EAX	//user
	MOV DWORD PTR [EDX], EAX

	//MessageBox
	MOV EDX,EBP
	ADD EDX,OFFSET r_szMessageBox
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET r_MessageBox
	MOV [EDX],EAX

	//Kernel
	MOV EDX,EBP
	ADD EDX,OFFSET r_szKernel32
	LEA EAX,[EDX]
	PUSH EAX
	MOV EDX,EBP
	ADD EDX,OFFSET r_LoadLibrary
	CALL [EDX]
	MOV EDX,EBP
	ADD EDX,OFFSET r_KernelBase
	MOV ESI,EAX	//kernel
	MOV DWORD PTR [EDX], EAX
	//KernelBase=LoadLibrary(szKernel32);
	
	//GetModuleHandle
	MOV EDX,EBP
	ADD EDX,OFFSET r_szGetModuleHandle
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET r_GetModuleHandle
	MOV [EDX],EAX

	//VirtualAlloc
	MOV EDX,EBP
	ADD EDX,OFFSET r_szVirtualAlloc
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET r_VirtualAlloc
	MOV [EDX],EAX

	//VirtualFree
	MOV EDX,EBP
	ADD EDX,OFFSET r_szVirtualFree
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET r_VirtualFree
	MOV [EDX],EAX

	//ExitProcess
	MOV EDX,EBP
	ADD EDX,OFFSET r_szExitProcess
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET r_ExitProcess
	MOV [EDX],EAX

	JMP start
//Получаем адрес функции
DoGetProcAddr:
	PUSH EAX
	PUSH ESI
	MOV EDX,EBP
	ADD EDX,OFFSET r_GetProcAddress
	CALL [EDX]
	//GetProcAddress(HMODULE hModule,LPCSTR lpProcName);
	RETN
start:

	MOV EDX,EBP            //смещение загрузки
	ADD EDX,OFFSET dw_Image_Base//переходим на метку dw_Image_Base
	MOV EAX,DWORD PTR [EDX]//получаем значение Image_Base
	ADD EAX,[EAX+03Ch]     //смещаемся на адрес PE-заголовка
	ADD EAX,6h//поле NumberOfSections
	MOV ESI,[EAX]//в esi кол-во секций
	ADD EAX,0F2h
	MOV EDI,EAX//в EDI адрес первой секции
	DEC ESI
	PUSH EBP
	POP EBX

	PUSH 0 
	ADD EBX,OFFSET r_GetModuleHandle
	CALL [EBX]
	SUB EBX,OFFSET r_GetModuleHandle 
	MOV EBP,EAX 
//Распаковка секций
unpack_section:

	MOV EAX,[EDI+10h]//считываем поле секции SizeOfRawData
	OR EAX,EAX
	JE end_unpack_sect//секция пуста
	MOVZX EAX,[EDI+22h]//считываем поле секции NumberOfLinenumbers - флаг упаковки
	OR EAX,EAX
	JE end_unpack_sect//секция не упаковывалась
	
	PUSH PAGE_READWRITE 
	PUSH MEM_COMMIT 
	PUSH [EDI+10h]//размер секции
	PUSH 0 
	ADD EBX,OFFSET r_VirtualAlloc
	CALL [EBX]//выделяем виртуальную память под секцию
	SUB EBX,OFFSET r_VirtualAlloc

	PUSH EAX 
	MOV EDX,EAX 
	MOV EAX,EBP 
	ADD EAX,[EDI+0Ch]//виртуальный адрес упакованной секции
	MOV ECX,[EDI+10h]//размер упакованной секции
	CALL move_mem//копируем память
	
	MOV EAX,[ESP]//источник
	MOV EDX,EBP 
	ADD EDX,[EDI+0Ch]//приемник
	CALL aP_depack//распаковка

	POP EAX 
	PUSH MEM_DECOMMIT 
	PUSH [EDI+10h] 
	PUSH EAX
	ADD EBX,OFFSET r_VirtualFree
	CALL [EBX]//удалим временный виртуальный буфер
	SUB EBX,OFFSET r_VirtualFree
end_unpack_sect: 
	ADD EDI,28h//следующая секция
	DEC ESI//счетчик секций
	JNE unpack_section

	ADD EBX,OFFSET dw_OEP_Import
	MOV ESI,DWORD PTR [EBX]
	SUB EBX,OFFSET dw_OEP_Import
	ADD ESI,EBP//старый адрес таблицы импорта
//Здесь происходит самое интересное - восстановление таблицы импорта!
next_import_entry: 
		
	MOV ECX,[ESI+12] //поле Name
	OR ECX,ECX 
	JE done          //конец таблицы?
	ADD ECX,EBP 
	MOV EDI,ECX 
	PUSH EDI 
	//Получим хэндл модуля
	ADD EBX,OFFSET r_GetModuleHandle
	CALL [EBX]
	SUB EBX,OFFSET r_GetModuleHandle
	OR EAX,EAX 
	JNE next1//модуль загружен?
 	PUSH EDI 
	//Если модуль не загружен еще - загрузим!
	ADD EBX,OFFSET r_LoadLibrary
	CALL [EBX]
	SUB EBX,OFFSET r_LoadLibrary 
next1: 
	OR EAX,EAX
	JNE next2//DLL была загружена?
	PUSH MB_ICONERROR 
	PUSH 0 
	PUSH EDI 
	PUSH 0 
	//Сообщение об отсутствии библиотеки
	ADD EBX,OFFSET r_MessageBox
	CALL [EBX]
	SUB EBX,OFFSET r_MessageBox
	PUSH 126 //Завершение с ошибкой(библиотека не найдена)
	ADD EBX,OFFSET r_ExitProcess
	CALL [EBX]
	SUB EBX,OFFSET r_ExitProcess
next2: 
	MOV EDI,EAX 
	MOV ECX,[ESI]//поле OriginalFirstThunk(имя первой функции)
	OR ECX,ECX 
	JNE next3 
	//Если мы здесь, значит таблица имен функций и IAT - физически одна таблица
	MOV ECX,[ESI+16]//поле FirstThunk
next3: 
	JECXZ next4//на следующую DLL
	ADD ECX,EBP//теперь в ECX указатель на таблицу с именами функций
	MOV EDX,[ESI+16]
	ADD EDX,EBP//в ЕDX - указатель на IAT
process_iat: 
	MOV EAX,[ECX] 
	OR EAX,EAX 
	JE next4//все функции данной DLL загружены?
	//определим по ординалу ли импортируется функция (старший бит = 1) 
	TEST EAX,80000000h 
	JE by_name//по имени
	AND EAX,0000FFFFh//если ординал, то оставляем значащие разряды 
	JMP iat_common//по ординалу
by_name: 
	ADD EAX,EBP//адрес структуры с именем функции
	ADD EAX,2//пропускаем поле Hint
iat_common: 
	PUSH ECX 
	PUSH EDX 
	PUSH EAX//имя функции
	PUSH EDI//хэндл DLL
	ADD EBX,OFFSET r_GetProcAddress
	CALL [EBX]
	SUB EBX,OFFSET r_GetProcAddress 
	POP EDX 
	POP	ECX 
	MOV [EDX],EAX//записываем в IAT адрес функции
	ADD ECX,4
	ADD EDX,4 
	JMP process_iat//к следующей функции
next4: 
	ADD ESI,20//к следующей DLL
	JMP next_import_entry 
done: 
//Возвращаемся на начальную точку входа
	MOV EDX,EBX
	ADD EDX,OFFSET dw_OEP
	MOV EAX,DWORD PTR [EDX]
	MOV EDX,EBX
	ADD EDX,OFFSET dw_Image_Base
	ADD EAX,DWORD PTR [EDX]
	JMP EAX
//Процедура для копирования памяти
//EAX - указатель на источник
//EDX - указатель на приемник
//ECX - размер данных 
move_mem: 
	PUSH ESI 
	PUSH EDI 
	MOV ESI,EAX//источник
	MOV EDI,EDX//приемник
	MOV EAX,ECX//размер
	CMP EDI,ESI 
	JA down 
	JE mexit 
	SAR ECX,2 
	JS mexit 
	REP MOVSD 
	MOV ECX,EAX 
	AND ECX,3 
	REP MOVSB 
	JMP mexit 
down: 
	LEA ESI,[ESI+ECX-4] 
	LEA EDI,[EDI+ECX-4] 
	SAR ECX,2 
	JS mexit 
	STD 
	REP MOVSD 
	MOV ECX,EAX 
	AND ECX,3 
	ADD ESI,3 
	ADD EDI,3 
	REP MOVSB 
	CLD 
mexit: 
	POP EDI 
	POP ESI 
	RET 
//Процедура распаковки данных, сжатых aPLib 
//EAX - указатель на источник
//EDX - указатель на приемник
aP_depack:
    //; aP_depack_asm(const void *source, void *destination)

    pushad

    mov    esi, eax
    mov    edi, edx

    cld
    mov    dl, 80h
    xor    ebx,ebx
litera:
    movsb
    mov    bl, 2
nexttag:
    call   getbit
    jnc    litera
    xor    ecx, ecx
    call   getbit
    jnc    codepair
    xor    eax, eax
    call   getbit
    jnc    shortmatch
    mov    bl, 2
    inc    ecx
    mov    al, 10h
getmorebits:
    call   getbit
    adc    al, al
    jnc    getmorebits
    jnz    domatch
    stosb
    jmp    nexttag
codepair:
    call   getgamma_no_ecx
    sub    ecx, ebx
    jnz    normalcodepair
    call   getgamma
    jmp    domatch_lastpos
shortmatch:
    lodsb
    shr    eax, 1
    jz     donedepacking
    adc    ecx, ecx
    jmp    domatch_with_2inc
normalcodepair:
    xchg   eax, ecx
    dec    eax
    shl    eax, 8
    lodsb
    call   getgamma
    cmp    eax, 32000
    jae    domatch_with_2inc
    cmp    ah, 5
    jae    domatch_with_inc
    cmp    eax, 7fh
    ja     domatch_new_lastpos
domatch_with_2inc:
    inc    ecx
domatch_with_inc:
    inc    ecx
domatch_new_lastpos:
    xchg   eax, ebp
domatch_lastpos:
    mov    eax, ebp
    mov    bl, 1
domatch:
    push   esi
    mov    esi, edi
    sub    esi, eax
    rep    movsb
    pop    esi
    jmp    nexttag
getbit:
    add    dl, dl
    jnz    stillbitsleft
    mov    dl, [esi]
    inc    esi
    adc    dl, dl
stillbitsleft:
    ret
getgamma:
    xor    ecx, ecx
getgamma_no_ecx:
    inc    ecx
getgammaloop:
    call   getbit
    adc    ecx, ecx
    call   getbit
    jc     getgammaloop
    ret
donedepacking:
    popad
    ret
//Данные для распаковки
r_szKernel32:			//db "Kernel32.dll",0,13
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
r_KernelBase:
	INT 3
	INT 3
	INT 3
	INT 3
r_szGetModuleHandle:    //db "GetModuleHandleA",0,17
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
r_GetModuleHandle:
	INT 3
	INT 3
	INT 3
	INT 3
r_szVirtualAlloc:     //db "VirtualAlloc",0,13
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
r_VirtualAlloc:
	INT 3
	INT 3
	INT 3
	INT 3
r_szVirtualFree:    //db "VirtualFree",0,12
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
r_VirtualFree:
	INT 3
	INT 3
	INT 3
	INT 3
r_szExitProcess:    //db "ExitProcess",0,12
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
r_ExitProcess:
	INT 3
	INT 3
	INT 3
	INT 3
r_szUser32:	    //db "User32.dll",0,11
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
r_UserBase:
	INT 3
	INT 3
	INT 3
	INT 3
r_szMessageBox:     //db "MessageBoxA",0,12
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
	INT 3
r_MessageBox:
	INT 3
	INT 3
	INT 3
	INT 3
dw_Image_Base:	
	INT 3
	INT 3
	INT 3
	INT 3
dw_OEP:
	INT 3
	INT 3
	INT 3
	INT 3
dw_OEP_Import:
	INT 3
	INT 3
	INT 3
	INT 3
r_LoadLibrary:
	INT 3
	INT 3
	INT 3
	INT 3
r_GetProcAddress:
	INT 3
	INT 3
	INT 3
	INT 3
dw_Old_size:
	INT 3
	INT 3
	INT 3
	INT 3
dw_Import_size:
	INT 3
	INT 3
	INT 3
	INT 3
UnpackerCodeEND:
	RET
//"UNPACKEND" - ключевое слово
	PUSH EBP //'U'       
	DEC ESI  //'N'
	PUSH EAX //'P'
	INC ECX	 //'A'
	INC EBX	 //'C'
	DEC EBX	 //'K'
	INC EBP	 //'E'
	DEC ESI	 //'N'
	INC ESP	 //'D'
    }
}
PIMAGE_SECTION_HEADER rva_to_section(PIMAGE_FILE_HEADER pFh, DWORD RVA)
{
	int i;
	IMAGE_SECTION_HEADER  *pSh;//заголовок секции
	//Считываем заголовок первой секции
	pSh = (PIMAGE_SECTION_HEADER)((DWORD)(pFh + 1) + pFh->SizeOfOptionalHeader);
	//Цикл по всем секциям
	for (i = 0; i < pFh->NumberOfSections; i++)
	{
		//Если запрашиваемый RVA указывает в диапазон RVA секции
		if (RVA >= pSh->VirtualAddress && RVA < pSh->VirtualAddress + pSh->Misc.VirtualSize)
			return pSh;//секция найдена
		++pSh;//переходим к следующей секции
	}
	return NULL;//секции не существует
}
DWORD get_func_rva(void* func_name)
{
	void *func_name_temp=func_name;
	char *pfunc_name_temp=PCHAR(func_name_temp);//преобразуем к указателю char*
	DWORD jmp_dw_RVA,dw_RVA;
	MoveMemory(&jmp_dw_RVA,pfunc_name_temp+1,4);//получаем смещение от указателя функции
	dw_RVA=DWORD(pfunc_name_temp)+jmp_dw_RVA+5;//получаем RVA
	return(dw_RVA);
}
DWORD get_func_size(void* func_name)
{
	DWORD dw_RVA=get_func_rva(func_name);
	char* pfunc_body=PCHAR(dw_RVA);//указатель на тело функции
	UCHAR byte;//очередной байт функции
	bool is_end=FALSE;
	char *unpacker_code_end=new char[10];
	DWORD len=0;//размер функции
	do
	{
		MoveMemory(&byte,pfunc_body+len,1);//считываем очередной байт
		//Пока не встретим команду RET, а за ней ключевое слово
		if(byte==0xC3)//код команды RET
		{
			MoveMemory(unpacker_code_end,pfunc_body+len+0x01,10);
			unpacker_code_end[9]=0x00;
			if(strcmp(unpacker_code_end,"UNPACKEND")==0)
			{
				is_end=TRUE;
			}
		}
		len++;
	}while(!is_end);
	return(len);
}
char* copy_func(void* func_name)
{
	DWORD dw_RVA=get_func_rva(func_name);//получаем RVA
	DWORD dw_Size=get_func_size(func_name);//получаем размер
	char* pfunc_body=PCHAR(dw_RVA);//указатель на тело функции
	char* file_buff=new char[dw_Size];//буффер для кода
	MoveMemory(file_buff,pfunc_body,dw_Size);//копируем тело функции
	return(file_buff);
}
void create_new_import_table(LPVOID base,DWORD raw_data,DWORD virt_addr)
{
	/*
	Для запуска упакованного файла потребуется создать новую таблицу импорта!
	Нам потребуется импортировать лишь две функции из Kernel32.dll.
	Это функции LoadLibraryA и GetProcAddress, остальные библиотеки и функции
	будут импортированы с помощью этих функций.
	*/
	LPVOID pAddress_IT=(LPVOID)((int)base+raw_data);
	//Очищаем таблицу импорта
	FillMemory(pAddress_IT,import_table_size,0x00);
	IMAGE_IMPORT_DESCRIPTOR import_descriptor;
	//Считываем элемент таблицы
	MoveMemory(&import_descriptor,pAddress_IT,sizeof(IMAGE_IMPORT_DESCRIPTOR));
	DWORD dw_raw=raw_data+2*sizeof(IMAGE_IMPORT_DESCRIPTOR);//указатель на место после IT
	//Адрес имя dll
	import_descriptor.Name=virt_addr+2*sizeof(IMAGE_IMPORT_DESCRIPTOR);
	MoveMemory((LPVOID)((int)base+dw_raw),Kernel,strlen(Kernel));//записываем имя dll
	dw_raw=dw_raw+strlen(Kernel)+1;//имя должно быть в виде ASCIIZ-строки
	//Заполняем поле FirstThunk(название импортируемых функций)
	import_descriptor.FirstThunk=dw_raw-raw_data+virt_addr;
	DWORD dw_raw_nf;//dw_row_nf - виртуальный адрес адрес с названием функции
	DWORD dw_raw1;//физический адрес с именем функции
	dw_raw1=dw_raw+10;//оставляем место для двух указателей + 2 байта для конца списка
	dw_raw_nf=dw_raw1-raw_data+virt_addr;//вычисляем вирт. адрес с именем функции
	MoveMemory((LPVOID)((int)base+dw_raw),&dw_raw_nf,4);//заносим его в таблицу
	dw_raw1=dw_raw1+2;//пропускаем поле Hint
	//Записываем в память имя функции(LoadLibraryA)
	MoveMemory((LPVOID)((int)base+dw_raw1),Load_Library,strlen(Load_Library));
	dw_raw1=dw_raw1+strlen(Load_Library);//переходим к след. функции
	dw_raw=dw_raw+4;//пропускай адрес первой
	dw_raw_nf=dw_raw1-raw_data+virt_addr;//вычисляем вирт. адрес с именем функции
	MoveMemory((LPVOID)((int)base+dw_raw),&dw_raw_nf,4);//заносим его в таблицу
	dw_raw1=dw_raw1+2;//пропускаем поле Hint
	//Записываем в память имя функции(GetProcAddress)
	MoveMemory((LPVOID)((int)base+dw_raw1),Get_Proc_Address,strlen(Get_Proc_Address));
	//Пишем таблицу импорта в файл
	MoveMemory(pAddress_IT,&import_descriptor,sizeof(IMAGE_IMPORT_DESCRIPTOR));
}
void init_loader_variables(char* pUnpack_code)
{
	DWORD dw_raw=unpacker_code_size;
	DWORD l;
	dw_raw = dw_raw - 1;//пропускаем RET
	//dw_Import_size DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&import_size,4);
	//dw_Old_size DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&old_size,4);
	//r_Get_Proc_Address  DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&rGetProcAddress,4);
	//r_Load_Library  DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&rLoadLibrary,4);
	//dw_OEP_Import DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&oep_import,4);
	//dw_OEP DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&oep,4);
	//dw_Image_Base	 DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&image_base,4);

	//r_MessageBox  DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&rMessageBox,4);
	//r_szMessageBox  DB "MessageBoxA",0
	l=DWORD(strlen(szMessageBox))+1;
	dw_raw = dw_raw - l;
	MoveMemory(pUnpack_code+dw_raw,szMessageBox,l);
	//r_UserBase  DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&dwUserBase ,4);
	//r_szUser32  DB "User32.dll",0
	l=DWORD(strlen(szUser32))+1;
	dw_raw = dw_raw - l;
	MoveMemory(pUnpack_code+dw_raw,szUser32,l);
	//r_ExitProcess  DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&rExitProcess,4);
	//r_szExitProcess  DB "ExitProcess",0
	l=DWORD(strlen(szExitProcess))+1;
	dw_raw = dw_raw - l;
	MoveMemory(pUnpack_code+dw_raw,szExitProcess,l);
	//r_VirtualFree  DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&rVirtualFree,4);
	//r_szVirtualFree  DB "VirtualFree",0
	l=DWORD(strlen(szVirtualFree))+1;
	dw_raw = dw_raw - l;
	MoveMemory(pUnpack_code+dw_raw,szVirtualFree,l);
	//r_VirtualAlloc  DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&rVirtualAlloc,4);
	//r_szVirtualAlloc  DB "VirtualAlloc",0
	l=DWORD(strlen(szVirtualAlloc))+1;
	dw_raw = dw_raw - l;
	MoveMemory(pUnpack_code+dw_raw,szVirtualAlloc,l);
	//r_GetModuleHandle  DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&rGetModuleHandle,4);
	//r_szGetModuleHandle  DB "GetModuleHandleA",0
	l=DWORD(strlen(szGetModuleHandle))+1;
	dw_raw = dw_raw - l;
	MoveMemory(pUnpack_code+dw_raw,szGetModuleHandle,l);
	//r_KernelBase  DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&dwKernelBase ,4);
	//r_szKernel32  DB "Kernel32.dll",0
	l=DWORD(strlen(szKernel32))+1;
	dw_raw = dw_raw - l;
	MoveMemory(pUnpack_code+dw_raw,szKernel32,l);
}
DWORD align(DWORD value,DWORD align)
{
	DWORD r;
	DWORD align_value;
	align_value=value;
	r=value%align;//получаем кол-во байт для выравнивания
	if(r!=0)//если не выравнена
	align_value+=align-r;//выравниваем
	return align_value;
}
bool file_is_pack()
{
	int i;
	char name[6]={'.','c','o','m','p','\0'};//имя новой секции
	PIMAGE_DOS_HEADER pDosh;
	PIMAGE_NT_HEADERS pNTh;
	LPVOID pBuf_exe_temp=pBuf_exe;
	pDosh=(PIMAGE_DOS_HEADER)pBuf_exe_temp;
	pNTh=(PIMAGE_NT_HEADERS)((int)pBuf_exe_temp+pDosh->e_lfanew);
	pBuf_exe_temp=(LPVOID)((int)pBuf_exe_temp+pDosh->e_lfanew+sizeof(_IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER pSecth=(PIMAGE_SECTION_HEADER)pBuf_exe_temp;
	for(i=0;i<pNTh->FileHeader.NumberOfSections;i++)
	{
		if(strcmp((char*)pSecth->Name,name)==0)
		{
			pSecth_comp=pSecth;
			return true;
		}
		++pSecth;//следующая секция в исходном файле
	}
	return false;
}
void depack_exe(_TCHAR *name_new_exe)
{
	PIMAGE_DOS_HEADER pDosh;
	PIMAGE_NT_HEADERS pNTh;
	DWORD size;

	DWORD delta=0;//смещение секции в файле
	DWORD size_of_image=0;//новое значение размера образа
	DWORD new_size_sect;
	DWORD align_RS;//выравненный виртуальный размер страницы
	int offset;//смещение в структуре IMAGE_SECTION_HEADER
	DWORD pRawData_exe,pRawData_new;//физ. смещения секций
	DWORD buf;
	DWORD wbuf;
	LPVOID pBuf_new_FS=pBuf_new;//сохраним адрес первой секции в новом файле
	LPVOID pBuf_exe_FS;//адрес первой секции в исходном
	int i;
	PIMAGE_SECTION_HEADER pSecth,pSecth_new;

	size=GetFileSize(hEXE,NULL);//получаем размер исходного файла
	MoveMemory(&old_size,(LPVOID)((int)pBuf_exe+size-9),4);
	new_size=old_size;
	MoveMemory(&oep,(LPVOID)((int)pBuf_exe+size-25),4);
	MoveMemory(&oep_import,(LPVOID)((int)pBuf_exe+size-21),4);
	MoveMemory(&import_size,(LPVOID)((int)pBuf_exe+size-5),4);
	hNew_exe=CreateFile(name_new_exe,GENERIC_READ | GENERIC_WRITE, 
			FILE_SHARE_READ | FILE_SHARE_WRITE,0,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,0);
	hTime=hNew_exe;
	//перемещае указатель на размер файла
	SetFilePointer(hTime, old_size,NULL,FILE_BEGIN);
	SetEndOfFile(hTime);//размер файла увеличивается до указанной величины
	hNEWmap=CreateFileMapping(hNew_exe, 0, PAGE_READWRITE, 0, 0, 0);
	pBuf_new_start=pBuf_new=MapViewOfFile(hNEWmap,FILE_MAP_ALL_ACCESS,0,0,0);

	pDosh=(PIMAGE_DOS_HEADER)pBuf_exe;//считываем dos-заголовок
	//копируем в новый файл dos-заголовок без изменений
	MoveMemory(pBuf_new,pBuf_exe,pDosh->e_lfanew);
	//перемещаем указатель на начало PE-заголовка в обоих файлах (pDosh->e_lfanew - адрес начала PE-заголовок)
	pBuf_exe=(LPVOID)((int)pBuf_exe+pDosh->e_lfanew	);
	pBuf_new=(LPVOID)((int)pBuf_new+pDosh->e_lfanew	);
	pNTh=(PIMAGE_NT_HEADERS)pBuf_exe;	//считываем PE-заголовок
	MoveMemory(pBuf_new,&(pNTh->Signature),sizeof(pNTh->Signature));//записываем сигнатуру
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->Signature));//смещаемся в новом файле
	MoveMemory(pBuf_new,&(pNTh->FileHeader.Machine),sizeof(pNTh->FileHeader.Machine));//записываем платформу
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->FileHeader.Machine));
	NumberOfSections=pNTh->FileHeader.NumberOfSections-1;//уменьшаем кол-во секции на 1 (для загрузчика)
	MoveMemory(pBuf_new,&(NumberOfSections),sizeof(pNTh->FileHeader.NumberOfSections));//количесто секций
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->FileHeader.NumberOfSections));
	//Поля TimeDateStamp, PointerToSymbolTable, NumberOfSymbols нас не интересуют
	//Поэтому пропустим их и перейдем к полю SizeOfOptionalHeader
	pBuf_new=(LPVOID)((int)pBuf_new+12);
	MoveMemory(pBuf_new,&(pNTh->FileHeader.SizeOfOptionalHeader),sizeof(pNTh->FileHeader.SizeOfOptionalHeader));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->FileHeader.SizeOfOptionalHeader));
	MoveMemory(pBuf_new,&(pNTh->FileHeader.Characteristics),sizeof(pNTh->FileHeader.Characteristics));//характеристики
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->FileHeader.Characteristics));
	//Далее переносим все поля опционального заголовка неизменными
	//Возможно, в дальнейшем некоторые из них будут модифицироваться
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader),0xE0);
	file_align=pNTh->OptionalHeader.FileAlignment;
	size_of_image=pNTh->OptionalHeader.SizeOfImage;
	pBuf_new=(LPVOID)((int)pBuf_new+0xE0);
	//С PE-заголовком пока все. Переходим к обработке секций
	//После перезаписи в новый файл опционального заголовка, pBuf_new указывает на начало первой секции
	//Переместим указатель исходного exe также на начало первой секции
	pBuf_exe=pBuf_exe_FS=(LPVOID)((DWORD)(&(pNTh->FileHeader) + 1) + pNTh->FileHeader.SizeOfOptionalHeader);
	pSecth=(PIMAGE_SECTION_HEADER)pBuf_exe;
	pSecth_new=(PIMAGE_SECTION_HEADER)pBuf_new;
	offset=sizeof(pSecth->Name)+12;
	delta=0;
	for(i=0;i<pNTh->FileHeader.NumberOfSections-1;i++)
	{
		MoveMemory((LPVOID)((int)pBuf_new),pSecth,IMAGE_SIZEOF_SECTION_HEADER);
		pRawData_exe=pSecth->PointerToRawData+(int)pBuf_exe_start;
		//Изменим физичекое смещение с учетом поправки
		pRawData_new=pSecth->PointerToRawData+delta;
		MoveMemory((LPVOID)((int)pBuf_new+offset),&(pRawData_new),sizeof(pRawData_new));
		pRawData_new+=(int)pBuf_new_start;
		if(pSecth->NumberOfLinenumbers==0xff)//если секция упаковывалась
		{
			new_size_sect=aP_depack_asm_fast((const void*)pRawData_exe,(LPVOID)pRawData_new);
			if(new_size_sect==APLIB_ERROR)
				printf("Depack error!");
			align_RS=align(new_size_sect,file_align);
			MoveMemory((LPVOID)((int)pBuf_new+offset-sizeof(pSecth->SizeOfRawData)),&(align_RS),sizeof(align_RS));
			buf=align_RS-pSecth->SizeOfRawData;
			align_RS=align(buf,file_align);
			delta=delta+align_RS;
			wbuf=0x00;//снимаем флаг упаковки
			MoveMemory((LPVOID)((int)pBuf_new+offset+14),&(wbuf),sizeof(wbuf));
		}
		else
		{
			copy_section(pRawData_exe,pRawData_new,pSecth->SizeOfRawData);//просто копируем
		}
		++pSecth;//следующая секция в исходном файле
		pBuf_new=(LPVOID)((int)pBuf_new+sizeof(IMAGE_SECTION_HEADER));// и в новом файле
	}
	size_of_image-=pSecth->Misc.VirtualSize;
	pNTh=(PIMAGE_NT_HEADERS)((int)pBuf_new_start+pDosh->e_lfanew);
	pNTh->OptionalHeader.SizeOfImage=size_of_image;
	pNTh->OptionalHeader.AddressOfEntryPoint=oep;
	pNTh->OptionalHeader.DataDirectory[1].VirtualAddress=oep_import;
	pNTh->OptionalHeader.DataDirectory[1].Size=import_size;
}