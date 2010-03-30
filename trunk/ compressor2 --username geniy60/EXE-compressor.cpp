// EXE-compressor.cpp
#include "stdafx.h"
#include "Windows.h"
#include "Dbghelp.h"
#include "conio.h"
//Глобальные переменные
HANDLE hEXE,hNew_exe;
HANDLE hEXEmap,hNEWmap;
char *pUnpacker_code;
DWORD unpacker_code_size;
LPVOID pBuf_exe,pBuf_exe_start,pBuf_new,pBuf_new_start;
WORD NumberOfSections;
WORD import_table_size=0x60;//размер таблицы импорта, помещаемой в начале 
DWORD lsize,hsize;//младшее и старшее двойнные слова размера файла(в байтах).
DWORD image_base;

DWORD rLoadLibrary = 0;
DWORD rGetProcAddress = 0;
//Константы
const char *Kernel = "Kernel32.dll";
const char *Load_Library = "LoadLibraryA";
const char *Get_Proc_Address = "GetProcAddress";
//Функции
void create_exe();//функция создания нового exe-файла
void changes_of_sections(PIMAGE_NT_HEADERS pNTh);//работа с секциями
void copy_section(DWORD psource,DWORD preceiver,DWORD size);//копирование секции
void pack_section();//сжимание секции
void loader();//загрузчик
void create_new_import_table(LPVOID base,DWORD row_data,DWORD virt_addr);//создаем таблицу импорта
PIMAGE_SECTION_HEADER rva_to_section(PIMAGE_FILE_HEADER pFh, DWORD RVA);//возвращает описание секции
DWORD get_func_rva(void* func_name);//получение RVA функции(загрузчика)
DWORD get_func_size(void* func_name);//получение размера функции(загрузчика)
char* copy_func(void* func_name);//копирует тело функции(загрузчика) в буфер
void init_loader_variables(char* pUnpack_code);//инициализируем переменные загрузчика
DWORD align(DWORD value,WORD align);//функция для выравнивания адресов

int _tmain(int argc, _TCHAR* argv[])
{
	_TCHAR* name_exe;
	if(argv[1])
	name_exe=argv[1];
	else {
		printf("File name is not found!");
		_getch();
		return 0;
	}
	HANDLE hTime;
	hEXE=CreateFile(name_exe,GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		0,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,0);
	if(hEXE==INVALID_HANDLE_VALUE)
	{
		printf("File is not found!");
		_getch();
		return 0;
	}
	unpacker_code_size=get_func_size(loader);//получаем размер загрузчика
	pUnpacker_code=new char[unpacker_code_size];//выделяем буфер под код загрузчика
	pUnpacker_code=copy_func(loader);//указатель на буфер с кодом загрузчика
	hNew_exe=CreateFile(__TEXT("new.exe"),GENERIC_READ | GENERIC_WRITE, 
		FILE_SHARE_READ | FILE_SHARE_WRITE,0,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,0);
	lsize=GetFileSize(hEXE,&hsize);//получаем размер исходного файла
	hTime=hNew_exe;
	//перемещае указатель на размер файла
	SetFilePointer(hTime, lsize+hsize*65536+unpacker_code_size+import_table_size,NULL,FILE_BEGIN);
	SetEndOfFile(hTime);//размер файла увеличивается до указанной величины
	hEXEmap=CreateFileMapping(hEXE, 0, PAGE_READWRITE, 0, 0, 0);
	pBuf_exe_start=pBuf_exe=MapViewOfFile(hEXEmap,FILE_MAP_ALL_ACCESS,0,0,0);
	hNEWmap=CreateFileMapping(hNew_exe, 0, PAGE_READWRITE, 0, 0, 0);
	pBuf_new_start=pBuf_new=MapViewOfFile(hNEWmap,FILE_MAP_ALL_ACCESS,0,0,0);
	//Переходим к созданию нового exe
	create_exe();
	//Закрываем все handle и уничтожаем отображения
	UnmapViewOfFile(pBuf_exe);
	UnmapViewOfFile(pBuf_new);
	CloseHandle(hEXEmap);
	CloseHandle(hEXE);
	CloseHandle(hNEWmap);
	CloseHandle(hNew_exe);
	return 0;
}
void create_exe()
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
	pNTh=(PIMAGE_NT_HEADERS)pBuf_exe;	//считываем PE-заголовок
	MoveMemory(pBuf_new,&(pNTh->Signature),sizeof(pNTh->Signature));//записываем сигнатуру
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->Signature));//смещаемся в новом файле
	MoveMemory(pBuf_new,&(pNTh->FileHeader.Machine),sizeof(pNTh->FileHeader.Machine));//записываем платформу
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->FileHeader.Machine));
	NumberOfSections=pNTh->FileHeader.NumberOfSections+1;//увеличиваем кол-во секции на 1 (для загрузчика)
	MoveMemory(pBuf_new,&(NumberOfSections),sizeof(pNTh->FileHeader.NumberOfSections));//количесто секций
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->FileHeader.NumberOfSections));
	//Поля TimeDateStamp, PointerToSymbolTable, NumberOfSymbols нас не интересуют (возможно пока)
	//Поэтому пропустим их и перейдем к полю SizeOfOptionalHeader
	pBuf_new=(LPVOID)((int)pBuf_new+12);
	MoveMemory(pBuf_new,&(pNTh->FileHeader.SizeOfOptionalHeader),sizeof(pNTh->FileHeader.SizeOfOptionalHeader));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->FileHeader.SizeOfOptionalHeader));
	MoveMemory(pBuf_new,&(pNTh->FileHeader.Characteristics),sizeof(pNTh->FileHeader.Characteristics));//характеристики
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->FileHeader.Characteristics));
	//Далее переносим все поля опционального заголовка неизменными
	//Возможно, в дальнейшем некоторые из них будут модифицироваться
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.Magic),sizeof(pNTh->OptionalHeader.Magic));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.Magic));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.MajorLinkerVersion),sizeof(pNTh->OptionalHeader.MajorLinkerVersion));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.MajorLinkerVersion));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.MinorLinkerVersion),sizeof(pNTh->OptionalHeader.MinorLinkerVersion));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.MinorLinkerVersion));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.SizeOfCode),sizeof(pNTh->OptionalHeader.SizeOfCode));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.SizeOfCode));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.SizeOfInitializedData),sizeof(pNTh->OptionalHeader.SizeOfInitializedData));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.SizeOfInitializedData));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.SizeOfUninitializedData),sizeof(pNTh->OptionalHeader.SizeOfUninitializedData));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.SizeOfUninitializedData));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.AddressOfEntryPoint),sizeof(pNTh->OptionalHeader.AddressOfEntryPoint));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.AddressOfEntryPoint));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.BaseOfCode),sizeof(pNTh->OptionalHeader.BaseOfCode));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.BaseOfCode));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.BaseOfData),sizeof(pNTh->OptionalHeader.BaseOfData));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.BaseOfData));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.ImageBase),sizeof(pNTh->OptionalHeader.ImageBase));
	image_base=pNTh->OptionalHeader.ImageBase;//базовый адрес
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.ImageBase));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.SectionAlignment),sizeof(pNTh->OptionalHeader.SectionAlignment));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.SectionAlignment));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.FileAlignment),sizeof(pNTh->OptionalHeader.FileAlignment));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.FileAlignment));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.MajorOperatingSystemVersion),sizeof(pNTh->OptionalHeader.MajorOperatingSystemVersion));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.MajorOperatingSystemVersion));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.MinorOperatingSystemVersion),sizeof(pNTh->OptionalHeader.MinorOperatingSystemVersion));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.MinorOperatingSystemVersion));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.MajorImageVersion),sizeof(pNTh->OptionalHeader.MajorImageVersion));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.MajorImageVersion));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.MinorImageVersion),sizeof(pNTh->OptionalHeader.MinorImageVersion));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.MinorImageVersion));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.MajorSubsystemVersion),sizeof(pNTh->OptionalHeader.MajorSubsystemVersion));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.MajorSubsystemVersion));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.MinorSubsystemVersion),sizeof(pNTh->OptionalHeader.MinorSubsystemVersion));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.MinorSubsystemVersion));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.Win32VersionValue),sizeof(pNTh->OptionalHeader.Win32VersionValue));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.Win32VersionValue));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.SizeOfImage),sizeof(pNTh->OptionalHeader.SizeOfImage));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.SizeOfImage));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.SizeOfHeaders),sizeof(pNTh->OptionalHeader.SizeOfHeaders));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.SizeOfHeaders));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.CheckSum),sizeof(pNTh->OptionalHeader.CheckSum));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.CheckSum));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.Subsystem),sizeof(pNTh->OptionalHeader.Subsystem));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.Subsystem));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.DllCharacteristics),sizeof(pNTh->OptionalHeader.DllCharacteristics));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.DllCharacteristics));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.SizeOfStackReserve),sizeof(pNTh->OptionalHeader.SizeOfStackReserve));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.SizeOfStackReserve));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.SizeOfStackCommit),sizeof(pNTh->OptionalHeader.SizeOfStackCommit));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.SizeOfStackCommit));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.SizeOfHeapReserve),sizeof(pNTh->OptionalHeader.SizeOfHeapReserve));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.SizeOfHeapReserve));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.SizeOfHeapCommit),sizeof(pNTh->OptionalHeader.SizeOfHeapCommit));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.SizeOfHeapCommit));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.LoaderFlags),sizeof(pNTh->OptionalHeader.LoaderFlags));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.LoaderFlags));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.NumberOfRvaAndSizes),sizeof(pNTh->OptionalHeader.NumberOfRvaAndSizes));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.NumberOfRvaAndSizes));
	MoveMemory(pBuf_new,&(pNTh->OptionalHeader.DataDirectory),sizeof(pNTh->OptionalHeader.DataDirectory));
	pBuf_new=(LPVOID)((int)pBuf_new+sizeof(pNTh->OptionalHeader.DataDirectory));
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
	DWORD old_hd_size;//старый размер заголовков
	DWORD align_VS;//выравненный виртуальный размер страницы
	int offset;//смещение в структуре IMAGE_SECTION_HEADER
	DWORD pRawData_exe,pRawData_new;//физ. смещения секций
	BYTE flag=1;//разрешение упаковки(0-нет,1-да)
	char name[5]={'.','c','o','m','p'};//имя новой секции
	DWORD EntryPoint;
	DWORD buf;
	LPVOID pBuf_new_FS=pBuf_new;//сохраним адрес первой секции в новом файле
	LPVOID pBuf_exe_FS;//адрес первой секции в исходном
	int i;
	PIMAGE_SECTION_HEADER pSecth,pSecth_new;
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
	//Виртуальный размер(физический, смещенный на 0x1000)
	align_VS=align(unpacker_code_size,0x1000);
	MoveMemory((LPVOID)((int)pBuf_new+offset),&(align_VS),sizeof(align_VS));
	offset+=sizeof(pSecth->Misc)+sizeof(pSecth->VirtualAddress);
	//Физический размер секции равен размеру загрузчика
	MoveMemory((LPVOID)((int)pBuf_new+offset),&(unpacker_code_size),sizeof(unpacker_code_size));
	size_of_image+=align_VS;//увеличиваем размер образа
	offset+=sizeof(pSecth->SizeOfRawData);
	//Вычисляем физическое смещение в файле новой секции
	//Путем суммирования смещения предыдущей секции и её выравненого размера
	pSecth=(PIMAGE_SECTION_HEADER)(LPVOID)((int)pBuf_new-sizeof(IMAGE_SECTION_HEADER));
	buf=align(pSecth->SizeOfRawData,0x1000);
	buf+=pSecth->PointerToRawData;
	MoveMemory((LPVOID)((int)pBuf_new+offset),&(buf),sizeof(buf));
	offset=offset-sizeof(pSecth->SizeOfRawData)-sizeof(pSecth->VirtualAddress);
	//Аналогично вычисляем виртуальный адрес новой секции
	buf=pSecth->VirtualAddress+pSecth->Misc.VirtualSize;
	EntryPoint=buf;
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
	buf=align((int)pBuf_new_FS+NumberOfSections*sizeof(IMAGE_SECTION_HEADER)-(int)pBuf_new_start,0x1000);
	//Переместимся к полю SizeOfHeaders
	pBuf_new=(LPVOID)((int)pBuf_new+44);
	MoveMemory((LPVOID)((int)pBuf_new),&(buf),sizeof(buf));
	//Определим новое значение образа(размер заголовков + размер секции)
	size_of_image+=buf;
	pBuf_new=(LPVOID)((int)pBuf_new-4);
	MoveMemory((LPVOID)((int)pBuf_new),&(size_of_image),sizeof(size_of_image));
	//Поскольку размер заголовков мог измениться, то вычислим смещение
	delta=buf-old_hd_size;
	//Возвращаем указатели на начало первых секций
	pBuf_exe=pBuf_exe_FS;
	pBuf_new=pBuf_new_FS;
	offset=sizeof(pSecth->Name)+12;
	/*
	Далее произведем упаковку секций методом ...?
	*/
	for(i=0;i<pNTh->FileHeader.NumberOfSections;i++)
	{
		flag=1;
		pSecth=(PIMAGE_SECTION_HEADER)pBuf_exe;
		pSecth_new=(PIMAGE_SECTION_HEADER)pBuf_new;
		//Вычисляем реальное местоположение секции в файле(с учетом адреса проецирования)
		pRawData_exe=pSecth->PointerToRawData+(int)pBuf_exe_start;
		//Изменим физичекое смещение с учетом поправки
		pRawData_new=pSecth_new->PointerToRawData+delta;
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
			//pack_section();//сжимаем секцию
			copy_section(pRawData_exe,pRawData_new,pSecth->SizeOfRawData);
		}
		pBuf_exe=(LPVOID)((int)pBuf_exe+sizeof(IMAGE_SECTION_HEADER));
		pBuf_new=(LPVOID)((int)pBuf_new+sizeof(IMAGE_SECTION_HEADER));
	}
	//Изменим физичекое смещение с учетом поправки для новой секции
	pSecth_new=(PIMAGE_SECTION_HEADER)pBuf_new;
	pRawData_new=pSecth_new->PointerToRawData+delta;
	MoveMemory((LPVOID)((int)pBuf_new+offset),&(pRawData_new),sizeof(pRawData_new));
	//pRowData_new+=(int)pBuf_new_start;
	//Создаем таблицу импорта для функционирования загрузчика
	create_new_import_table(pBuf_new_start,pRawData_new,pSecth_new->VirtualAddress);
}
void copy_section(DWORD psource,DWORD preceiver,DWORD size)
{
	LPVOID s=(LPVOID)psource,r=(LPVOID)preceiver;
	MoveMemory(r,s,size);
}
void pack_section()
{
	/*Заглушка*/
}
void loader()
{
	/*Заглушка*/
	_asm
	{
UnpackerCode:
	PUSHAD
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
	ADD EDX,OFFSET r_Load_Library//в edx адрес поля r_Load_Library
	MOV [EDX],EBX	       //запоминаем адрес функции LoadLibraryA
	ADD EAX,04h            //переходим к следующей функции
	MOV EBX,DWORD PTR [EAX]//считываем адреса функции!
	MOV EDX,EBP            //смещение загрузки
	ADD EDX,OFFSET r_GetProcAddress//в edx адрес поля r_GetProcAddress
	MOV DWORD PTR [EDX],EBX//запоминаем адрес функции GetProcAddress

dw_Image_Base:	
	INT 3
	INT 3
	INT 3
	INT 3
r_Load_Library:
	INT 3
	INT 3
	INT 3
	INT 3
r_GetProcAddress:
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
	dw_raw = dw_raw - 1;//пропускаем RET
	//r_Get_Proc_Address  DD 0
	dw_raw = dw_raw - 4;
	CopyMemory(pUnpack_code+dw_raw,&rGetProcAddress,4);
	//r_Load_Library  DD 0
	dw_raw = dw_raw - 4;
	CopyMemory(pUnpack_code+dw_raw,&rLoadLibrary,4);
	//dw_Image_Base	 DD 0
	dw_raw = dw_raw - 4;
	MoveMemory(pUnpack_code+dw_raw,&image_base,4);
}
DWORD align(DWORD value,WORD align)
{
	WORD r;
	DWORD align_value;
	align_value=value;
	r=value%align;//получаем кол-во байт для выравнивания
	if(r!=0)//если не выравнена
	align_value+=align-r;//выравниваем
	return align_value;
}