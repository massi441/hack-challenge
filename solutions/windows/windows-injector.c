#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <Windows.h>

// note : compiled with gcc -shared -fPIC -o windows-injector.dll windows-injector.c

// the goal is to create a fake validator by reproducing the same memory layout found in ghidra.
// once the memory layout matches we can use it to inject custom functions.

// Constants
static const uint64_t validator_offset = 0x5000;

struct FakeValidatorVTable {
    void (*fake_hasher)();
    bool (*fake_checker)();
    void (*fake_destructor)();
    void (*fake_destructor2)();
};

struct FakeValidator {
    struct FakeValidatorVTable* v_table;
};

static struct FakeValidatorVTable fake_vtable;
static struct FakeValidator fake_validator;

bool fake_check() {
    // from here we can also call any other custom function that we want.
    // for example if this was a game we could install a cheat that gives us infinite health, or maybe infinite coins.
    // we pretty much have full control over the program from here, that's why code injection is so powerful
    printf("Bypassing auth.\n");
    return true;
}

void fake_hash() {
    printf("Performing fake hash");
    return;
}

void fake_destructor() {
    printf("Performing fake destruction");
    return;
}

void inject() {
    // fake vtable setup
    fake_vtable.fake_hasher = &fake_hash;
    fake_vtable.fake_checker = &fake_check;
    fake_vtable.fake_destructor = &fake_destructor;
    fake_vtable.fake_destructor2 = &fake_destructor;

    // fake validator setup
    fake_validator.v_table = &fake_vtable;

    // vtale overwriting
    uint64_t main_address = (uint64_t)GetModuleHandle(NULL); // this returns the base address of the main target

    void* original_validator = (void*)(main_address + validator_offset);

    memcpy(original_validator, &fake_validator, sizeof(fake_validator));
}

// the entrypoint of the dll, similar idea to a main function in a program
BOOL WINAPI DllMain(HINSTANCE hdll, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        inject();

        printf("Injected fake validator\n");
    }

    return TRUE;
}
