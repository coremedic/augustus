# Augustus
Augustus is a C++ implementation of CCob's "ThreadlessInject" and Maldev Academy's "RemoteTLSCallbackInjection"

### Features
- Compile-time hashing of Win32 API Functions
- Decrypt payload using the "tiny-AES-c" library

### Upcoming Features
- [ ] Use patchless hooking via debugger attachment and hardware breakpoints [(https://www.pentestpartners.com/security-blog/patchless-amsi-bypass-using-sharpblock)](https://www.pentestpartners.com/security-blog/patchless-amsi-bypass-using-sharpblock/).
- [ ] Avoid RWX on hooked function.  Hook assembly will need to handle VirtualProtect calls.
- [ ] Support any DLL via remote module enumeration.
- [ ] Brute force decrypt payload from .rsrc section.
- [ ] Use direct syscalls instead of Win32 API functions