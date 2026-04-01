#include <iostream>
#include <random>

// Thus, the base PasswordValidator class. '= 0' on a function marks it as abtstract.
// Thus, the class becomes abstract since it has at least one absract method.
// Hint:
//  The class has at least one virtual function. A virtual function makes a class polymorphic.
//  For every instance of a polymorphic class, the compiler adds a hidden 'vtable' pointer at offset 0x0 on the object instance
//  That vtable pointer is a pointer to an array of functions: In this case of a PasswordValidator, the array of functions 
//  would contain entries for : <checkPassword>, <hashPassword>, and ~PasswordValidator. (This can be verified in Ghidra)
class PasswordValidator {
public:
    virtual bool checkPassword(std::string pwd) = 0;
    virtual void hashPassword(std::string pwd) = 0;
    virtual ~PasswordValidator() {}
};

// Concrete implementation of a passsword validator, note that this class is not used anywhere in the program,
// it's simply defined to add more artifacts to analyze in the decompiler.
class SecurePasswordValidator : public PasswordValidator {
public:
    void hashPassword(std::string pwd) override {
        std::cout << "Hashing password..." << std::endl;
    }

    bool checkPassword(std::string pwd) override {
        return pwd == "SecurePassword12345!";
    }
};

// A random password validator. This is the actual password validator used by the program.
// What makes it so hard to guess the password is that it generates a new random password everytime, which is basically
// impossible to guess. This is why the solution requires bypassing the authentication system entirely.
class RandomPasswordValidator : public PasswordValidator {
public:
    void hashPassword(std::string pwd) override {
        std::cout << "Hashing password..." << std::endl;
    }

    bool checkPassword(std::string pwd) override {
        return pwd == generatePassword();
    }

private:
    // generates a random cryptocraphically secure password with a default length of 256 characters. Virtually impossible to guess
    static std::string generatePassword(int length = 256) {
        const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        std::random_device random;
        std::uniform_int_distribution<int> dist(0, sizeof(chars) - 2);

        std::string password(length, '\0');
        for (char& c : password) {
            c = chars[dist(random)];
        }

        return password;
    }
};

// the function called to authenticate the user when the program starts. It takes a pointer to a PasswordValidator,
// meaning the underlying type can be any implementation of PasswordValidator.
bool authenticate(PasswordValidator* validator) {
    std::cout << "Enter your password: ";
    std::string pwd;

    std::cin >> pwd;

    return validator->checkPassword(pwd);
}

// The **global** instance of the password validator used by the program
// Hint: This validator instance is the vulnerability/entry point for the code injection
RandomPasswordValidator validator = RandomPasswordValidator();

int main() {
    bool authenticated = authenticate(&validator);

    if (authenticated) {
        std::cout << "Access granted, entering adming portal..." << std::endl;
    } else {
        std::cout << "Access denied, invalid password" << std::endl;
    }

    return 0;
}
