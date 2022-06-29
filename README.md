# A collection of a couple different types of dll injection methods on windows.
## Structure
* `DummyProcess/` has the code for the dummy target process to inject the dll into
* `DllSource/` has the code for a simple dll whose DllMain just cout's a message then exits
* `DllInjector/` is the cli application with support for the different types of injection (x86/x64)
* The source for each injection method is defined in the `bool <injection method>::inject(DWORD dwTargetPid, std::string dllpath)` method which can be found in the respectively name cpp files in the `DllInjector/InjectionMethods/` directory.
* `DbgUtils/` just had a file with some stripped windows structs that I used in conjucntion with x64dbg for debugging
## Build
* Visual Studio using MSVC