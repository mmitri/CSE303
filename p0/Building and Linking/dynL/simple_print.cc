#include <iostream>
#include <string>

// to export a function, it must have C linkage
extern "C"{
    /// Print a newline-terminated message to the console
    ///
    /// @param message The message to print
    void simple_print(std::string message){
        std::cout << message << std::endl;
    }
}