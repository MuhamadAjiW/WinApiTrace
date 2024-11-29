// WinApiTrace.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <iostream>
#include <Windows.h>
#include <detours/detours.h>

#include "misc.h"

int main(){
    something();

    if (DetourIsHelperProcess()) {
        std::cout << "Detour is helper process!\n";
        return TRUE;
    }
    else {
        std::cout << "Detour is not helper process!\n";
        return FALSE;
    }

    return 0;
}
