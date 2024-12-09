# WinApiTrace

Application of Microsoft [Detour](https://github.com/microsoft/Detours)'s for API tracing. Used to gather API data for ransomware detection.

## How to Run

Get the executables on the github [releases](https://github.com/MuhamadAjiW/WinApiTrace/releases).
1. Unzipped the downloaded file go to the unzipped folder
2. Open a powershell or terminal
3. Run `.\sample.exe` to start listening for the calls
4. Start tracing by calling `.\withdll.exe /d:traceapi.dll <path-to-executable>` on another terminal
5. Traced API calls will be printed on the first terminal 

## How to Build
### Prerequisite

To build and run this program, you will need 
- Windows 10/11 (64 bit)
- [Visual Studio](https://visualstudio.microsoft.com/), any edition will do
- C\C++ installed on the Visual Studio

### Steps
1. Open the .sln on Visual Studio
2. Build the solution
3. Build output is in `rootdir/<architecture>/<buildmode>`

Then you can run the program as usual
