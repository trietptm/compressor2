#include "stdafx.h"
#include <stdio.h>
#include <locale>
#include <malloc.h>
#include <conio.h>
#include <string.h>
#include "Windows.h"
using namespace std;

#define MAX_BITS  15 //размер кода
#define INC_SIZE  256//увеличение размера кода
#define END_FILE  257//конец входных данных
#define TAB_RESET 258//сброс таблицы
#define MAX_CODE  1<<MAX_BITS//максимальный код
#define EMPTY     MAX_CODE//признак пустоты
//Разрядность кода и соответствующий ей размер
#if MAX_BITS==15
 #define TAB_SIZE 35531
#endif
#if MAX_BITS==14
 #define TAB_SIZE 18041
#endif
#if MAX_BITS==13
 #define TAB_SIZE 9029
#endif
#if MAX_BITS<=12
 #define TAB_SIZE 5021
#endif
FILE  *infile, *outfile;
BYTE  code_size=9;//начальная разрядность кода
WORD  next_code=259;//начальный свободный код
WORD  sp=0;//переменная для стека
WORD  w_buf=0;//буфер для сжатия
DWORD r_buf=0;//буфер для распаковки
DWORD tmp_buf=0;//временный буфер
BYTE  free_bits=16;//биты для помещения кода

WORD *code;//массив кодов
WORD *str;//массив закодированных строк(в виде кодов)
BYTE *symb;//массив входных символов
BYTE stack[MAX_CODE];//стек для декодирования строк
//Записывает в выходной файл код строки
void put_code(WORD c) 
{
	//Так как алгоритм основан на представлении кодов не в байтах, 
	//а в битах,то каждый бит слова формируется отдельно.
	//Соответственно, слово может содержать в себе части нескольких кодов
	if(free_bits>=code_size)//если код меньше чем свободных битов 
	{
		w_buf<<=code_size;//освобождаем место для нового кода
		w_buf|=c;//пишем его
		if(free_bits==code_size)//используются все свободные биты 
		{
			fwrite(&w_buf,2,1,outfile);//пишем в выходной файл
			free_bits=16;//обновляем счетчик свободных битов
			return;
		}
		free_bits-=code_size;//не все биты данного слова использованы
	}
	else//если код больше чем кол-во свободных битов 
	{
		w_buf<<=free_bits;//освобождаем оставшиеся место
		//записываем в его ту часть кода, которая помещается
		w_buf|=c>>(code_size-free_bits);
		fwrite(&w_buf,2,1,outfile);//пишем в выходной файл
		w_buf=c;//запоминаем код, так как он не полностью записан в файл
		//свободное место в слове с учетом остатка от предыдущего кода
		free_bits+=16-code_size;
	}
}
//Записывает в выходной файл последние биты
void flush_buf() 
{
	if(free_bits!=16)//есть не записанные биты
	{
		w_buf<<=free_bits;
		fwrite(&w_buf,2,1,outfile);
		free_bits=16;
	}
}
//Считывает очередной код из закодированного файла
WORD get_code() 
{
	WORD c;
	c=r_buf>>(32-code_size);//получаем очередной код
	r_buf<<=code_size;//стираем считанный код из буфера
	free_bits+=code_size;//свободное место в массиве r_buf
	//Если в массив r_buf можно поместить слово или более
	if(free_bits>=16) 
	{
		tmp_buf=0;//временный массив
		fread(&tmp_buf,2,1,infile);//читаем 2 байта
		//смещаем их на кол-во свободного места в старшем слове массива r_buf
		tmp_buf<<=free_bits-16; 
		r_buf|=tmp_buf;//записываем в анализируемый буфер
		free_bits-=16;//умен. кол-во свободного места на слово    
	}
	return c;//возвращаем код
}
//Получение хэш
WORD hash(WORD h_pref,BYTE h_root)
{
	/* 
	   Данная функция ускоряет поиск необходимой строки,
	   т. к. не требуется сравнения со всеми строками.
	   Достаточно сгенерировать хэш-индекс и смещение 
	   для данного индекса
	*/
	int index;
	int offset;
	index=(h_root<<(code_size-8))^h_pref;//хэш индекс
	if(index==0) offset=1;//смещение для индекса
	else offset=TAB_SIZE-index;
	while (1) 
	{
		if(code[index]==EMPTY) return index;//запись в таблице свободна
		if(str[index]==h_pref && symb[index]==h_root) return index;//данный код уже есть в таблице
		index-=offset;
		if(index<0) index+=TAB_SIZE;//возвращаемся на конец таблицы
	}
}
//Декодирование строки
void dec_string(WORD c) 
{
	while(1)//пока строка не полностью расшифрована
	{        
		stack[sp++]=symb[c];//запоминаем символ в стек   
		if(str[c]==EMPTY) break;//если это простейший символ(0-255)
		c=str[c];//строка не полностью расшифрована        
	}
}
//Функция сжатия
void compress(DWORD psource,DWORD preceiver,DWORD size) 
{
	infile=(FILE*)psource;
	outfile=(FILE*)preceiver;
	WORD cur_str;//текущая строка
	BYTE cur_char;//текущий входной символ
	WORD index;   //индекс в таблице
	DWORD bytes_left;      //кол-во не обработанных байтов
	WORD  i;
 
	printf("Compressing...   \n");
	code=(WORD*)malloc(TAB_SIZE*sizeof(WORD));
	str=(WORD*)malloc(TAB_SIZE*sizeof(WORD));
	symb=(BYTE*)malloc(TAB_SIZE*sizeof(BYTE));
	if(code==NULL || str==NULL || symb==NULL) 
	{
		printf("Fatal error allocating table space!\n");
		return;
	}
	for(i=0; i<=TAB_SIZE-1; i++) code[i]=EMPTY;//очищаем таблицу кодов
	bytes_left=size;//размер сжимаемого блока
	cur_str=fgetc(infile);//считываем первый символ 
	bytes_left--;
	//Пока не обработаем весь входной поток
	while(bytes_left--)
	{   
		cur_char=fgetc(infile);//очередной символ
		//Смотрим есть ли строка в таблице
		index=hash(cur_str,cur_char);
		//Если есть, то получаем значение кода
		if(code[index]!=EMPTY) 
		{
			cur_str=code[index];
		}
		else //Иначе, добавляем новый код в таблицу
		{
			code[index]=next_code++;//получаем свободный код
			str[index]=cur_str;
			symb[index]=cur_char;
			put_code(cur_str);//записываем в выходной файл
			cur_str=cur_char;//новая строка
			//Если код нельзя закодировать текущим количеством битов
			if(next_code>>code_size) 
			{
				if(next_code==MAX_CODE)//все коды заняты
				{
					//очищаем таблицу
					for(i=0;i<=TAB_SIZE-1;i++) code[i]=EMPTY;
					put_code(TAB_RESET);//код очистки таблицы
					next_code=259;//первый свободный код
					code_size=9;//сброс битов кодировки
				}
				else //не все коды заняты
				{
					put_code(INC_SIZE);//код увеличения разрядности кода
					code_size++; 
				}
			}
		}
	}
	printf("Done!\n"); 
	put_code(cur_str);
	free(code); free(str); free(symb);
	put_code(END_FILE);//символ конца данных 
	flush_buf();//выталкиваем оставшиеся биты
}
//Функция распаковки
void decompress(DWORD psource,DWORD preceiver) 
{
	WORD new_code;
	WORD old_code;
	WORD i;

	printf("Decompressing... \n");            
	str=(WORD*)malloc(TAB_SIZE*sizeof(WORD));
	symb=(BYTE*)malloc(TAB_SIZE*sizeof(BYTE));
	if(str==NULL || symb==NULL) 
	{
		printf("Fatal error allocating table space!\n");
		return;
	}
	for(i=0;i<=255;i++) 
	{
		symb[i]=i;//заполняем стандартными кодами от 0 до 255 (8 бит)
		str[i]=EMPTY;
	}
	fread(&r_buf,2,1,infile);//считываем слово
	r_buf<<=16;
	old_code=get_code();//получаем код
	fputc(old_code,outfile);//записываем в файл
	//Пока не считаем код конца данных
	while((new_code=get_code())!=END_FILE) 
	{
		if(new_code==TAB_RESET)//сброс таблицы
		{
			//сбрасываем все значения по умолчанию
			code_size=9; 
			next_code=259;
			old_code=get_code();//а также считываем
			fputc(old_code,outfile);//и пишем очередной символ
			continue;
		}
		if(new_code==INC_SIZE)//увеличение разрядности кода
		{
			code_size++;
			continue;
		}
		if(new_code<next_code)//код уже в таблице
		{
			dec_string(new_code);
			for(i=1; i<=sp; i++) fputc(stack[sp-i],outfile);//вывод с конца
		}
		else//особый случай, когда кода нет в таблице
		{
			dec_string(old_code);//декодируем старый код
			for(i=1; i<=sp; i++) fputc(stack[sp-i],outfile);//вывод с конца
			fputc(stack[sp-1],outfile);//плюс первый символ строки
		}
		str[next_code]=old_code;//старый код
		symb[next_code]=stack[sp-1];//первый символ строки
		old_code=new_code;//новый код - старый код
		next_code++; sp=0;            
	}
	printf("Done!\n");
	free(str); free(symb);
}