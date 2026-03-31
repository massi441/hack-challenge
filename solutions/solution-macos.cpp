#include <iostream>
#include <dlfcn.h>
#include <mach-o/dyld.h>

// malicious password hasher
void maliciousHasher(void* validator, std::string password) {
    std::cout << "Injection successful, doing a fake hash before executing malicious code" << std::endl;
    return;
}

// malicious password checker
bool maliciousChecker(void* validator, std::string password) {
    std::cout << "Injection successful, bypassing auth entirely" << std::endl;
    return true; // return true to by pass auth entirely
}

void maliciousDesctructor(void* validator) {
    std::cout << "Injected code in destructor" << std::endl;
    return;
}

// Medium difficulty constant
static constexpr const char* ValidatorSymbol = "validator"; // for if the binary contains symbols

// Hard difficulty constants
static constexpr uint64_t ValidatorOffset = 0x100008000; // found from the dissassembler
static constexpr const char* TargetName = "main-hard-macos"; // name of the target executable to inject code into

// this struct essentially recreates the vtable layout of a PasswordValidator
// Using a struct instead of recreating a class with the same memory layout
// means this solution would also work if the program was written with C.
struct MaliciousVtable {
    bool (*fakeChecker)(void*, std::string) = &maliciousChecker;
    void (*fakeHasher)(void*, std::string) = &maliciousHasher;
    void (*fakeDestructor)(void*) = &maliciousDesctructor;
    void (*fakeDestructor2)(void*) = &maliciousDesctructor;
}; 

static MaliciousVtable maliciousVtable = MaliciousVtable();

// On macos, the variable for running a process with a dynamic library is : DYLD_INSERT_LIBRARIES
// e.g. DYLD_INSERT_LIBRARIES=./mylib.dylib ./main
// Note: a dynamic library is a library that gets dynamically linked to a program at runtime
// '__attribute__((constructor))' means the inject() function is executed when the dynamically is linked. it's like a "main"
// function, but for a dynamic library.
// the same logic can be used on windows to inject code dynamically into a process

__attribute__((constructor))
void inject() {
    std::cout << "-------------------------------------------------" << std::endl; 
    std::cout << "Injecting fake password validator into program..." << std::endl;
    std::cout << "-------------------------------------------------" << std::endl;

    void* validator = nullptr;

    #ifdef MEDIUM // solution for the medium version
        void* lookupHandle = dlopen(NULL, RTLD_NOW);
        if (!lookupHandle) {
            std::cout << "Code injection failed, no handle found" << std::endl;
            std::cout << dlerror() << std::endl;
            return;
        }

        validator = dlsym(lookupHandle, ValidatorSymbol);
        if (!validator) {
            std::cout << "Code injection failed, no validator found" << std::endl;
            std::cout << dlerror() << std::endl;
            return;
        }
    #else // solution for the hard version
        uint32_t imageCount = _dyld_image_count();

        for (int i = 0; i < imageCount; i++) {
            const char* imageName = _dyld_get_image_name(i);
            if (strstr(imageName, TargetName)) {
                intptr_t aslrOffset = _dyld_get_image_vmaddr_slide(i); // gets the aslr offset of the main process

                uint64_t validatorAddress = ValidatorOffset + aslrOffset;

                validator = reinterpret_cast<void*>(validatorAddress);

                break;
            }
        }
    #endif 

    if (validator) {
        void* maliciousTablePtr = &maliciousVtable;
        
        std::memcpy(validator, &maliciousTablePtr, sizeof(void*));
        
        std::cout << "Successfully injected validator" << std::endl;
    } else {
        std::cout << "Failed to inject validator" << std::endl;
    }
}
