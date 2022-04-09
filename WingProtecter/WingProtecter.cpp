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

