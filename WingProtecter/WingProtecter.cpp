//
// GNU AFFERO GENERAL PUBLIC LICENSE
//Version 3, 19 November 2007
//
//Copyright(C) 2007 Free Software Foundation, Inc.
//Everyone is permitted to copyand distribute verbatim copies
//of this license document, but changing it is not allowed.
// Author : WingSummer （寂静的羽夏）
// 
//Warning: You can not use it for any commerical use,except you get 
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

#include <iostream>

#include "CWingProtect.h"

using namespace WingProtect;

int main()
{

	WingProtect::CWingProtect protecter(L"C:\\Users\\wingsummer\\Desktop\\ConsoleApplication1.exe", 50);

	if (protecter.Proctect(Protections::AllProtect))
	{
		cout << "加密成功！" << endl;
		if (protecter.Save2File(L"C:\\Users\\wingsummer\\Desktop\\ConsoleApplication1_p.exe"))
		{
			cout << "保存成功！" << endl;
		}
		else
		{
			cout << "虽然加密成功，但保存失败！" << GetLastError() << endl;
			cin.get();
		}
	}
	else
	{
		cout << "加密失败！" << endl;
		cin.get();
	}
	return 0;
}

