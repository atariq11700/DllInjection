# A collection of a couple different types of dll injection methods on windows.
## Structure
* `DummyProcess/` has the code for the dummy target process to inject the dll into
* `DllSource/` has the code for a simple dll whose DllMain just cout's a message then exits
* `DllInjector/` is the cli application with support for the different types of injection (64bit only right now)
* The source for each injection method is defined in the `bool <injection method>::inject(DWORD dwTargetPid, std::string dllpath)` method which can be found in the respectively name cpp files in the `DllInjector/InjectionMethods/` directory.
## Build
* Right now building is done with g++ and the command line. I have added vscode tasks to streamline this. Makefiles to come in the future.
* Currently only supports 64bit applications and dll's since my MINGW64 environment is only setup for 64bit. If your environment is properly setup for 32bit, you can define the _WIN32 macro and build using the -m32 flag passed to g++ for 32bit support. 