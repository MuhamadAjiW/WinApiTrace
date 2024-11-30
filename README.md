# WinApiTrace

Simple suite of Microsoft [Detour](https://github.com/microsoft/Detours)'s sample for API tracing. May be modified here and there for other purposes. Main credits goes to Microsoft.

## How to Run

Get the executables on the github [releases](https://github.com/MuhamadAjiW/WinApiTrace/releases).
1. Unzipped the downloaded file go to the unzipped folder
2. Run `.\syelogd.exe` on a terminal
3. Start tracing by calling `.\withdll.exe -d:traceapi.dll <path-to-executable>` on another terminal
4. Traced API calls will be printed on the `syelogd` terminal 

## How to Build
### Prerequisite

To build and run this program, you will need 
- Windows 10/11
- [Visual Studio](https://visualstudio.microsoft.com/), any edition will do
- C\C++ installed on the Visual Studio

### Steps
1. Open the .sln on Visual Studio
2. Build the solution
3. Build output is in `rootdir/<architecture>/<buildmode>`

Then you can run the program as usual