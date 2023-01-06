#include <iostream>
#include <unistd.h>
#include <string>
#include <map>
#include <dlfcn.h>
#include <vector>
#include "menu.h"

using namespace std;

/// The text to use in any module invocation
string current_text = "";

/// A collection of functions that we can invoke
///
/// NB: functions must have C linkage!
extern "C"{
    typedef void(*funct)(string); // pointer to a function taking a string
}

/// A map of string/function pairs
map<string, funct> functions;

/// All of the currently open .so files
vector<void*> open_handles;

/// Get text from the user
void getText(){
    cout <<"Enter some text:>";
    getline(cin, current_text);
    if(current_text == ""){
        cin.clear();
    }
}

/// Register a function. First fet the so name and open it, or fail. Then
/// get the function name and find it, or fail. Then get a string to use to
/// remember the function, and put it in the map.
void registerFunction(){
    string so_name, func_name, reg_name;

    // so name
    cout << "Enter the name of the .so file, or ctrl-D to return :>";
    getline(cin, so_name);
    if(so_name == ""){
        cin.clear();
        return;
    }
    void *handle = dlopen(so_name.c_str(), RTLD_LAZY);
    if(!handle){
        cout << "ERROR 322: Opening file" << so_name << endl;
        return;
    }

    // function
    cout << "Enter the function name to load, or ctrl-D to return :>";
    getline(cin, func_name);
    if(func_name == ""){
        dlclose(handle);
        cin.clear();
        return;
    }
    funct f = (funct)dlsym(handle, func_name.c_str());
    char *error;
    if((error = dlerror()) != NULL){
        cout << "ERROR 122: Locating " << func_name << " in " << so_name << endl;
        dlclose(handle);
        return;
    }

    // string key
    cout << "Enter the name to use when remembering this function, or ctrl-D to ""return :> ";
    getline(cin, reg_name);
    if(reg_name == ""){
        dlclose(handle);
        cin.clear();
        return;
    }
    // save the function
    functions.insert(std::make_pair(reg_name, f));

    // NB: we can not close the .so or we lose the reference to the function.
    // Save the handle here, clean it on exit from the program
    open_handles.push_back(handle);
}

// List all keys in the map
void listKeys(){
    cout << "Functions (one per line)" << endl;
    for(auto i = functions.begin(), e = functions.end(); i != e; ++i){
        cout << i->first << endl;
    }
    cout << endl;
}

/// Get a function by name and invoke it
void invoke(){
    // get function name
    string f_name;
    cout << "Enter the function name to use :>";
    getline(cin, f_name);
    if(f_name == ""){
        cin.clear();
        return;
    }

    // get function
    auto it = functions.find(f_name);
    if(it == functions.end()){
        cout << "Could not find function" << endl;
        return;
    }

    // invoke function
    it->second(current_text);
}

int main(int argc, char **argv){
    // repeatedly print the menu and handle a choice
    int choice = -1;
    while (choice != 5){
        menu(current_text);
        choice = -1;
        string choice_string;
        // NB: use the return value of getline to detect EOF, prevent infinite loop
        getline(cin, choice_string);
        if(choice_string == ""){
            cin.clear();
            choice_string = "z"; // force an error message
        }
        if(choice_string[0] >= '1' && choice_string[0] <= '5'){
            choice = choice_string[0] - 0x30;
        }else{
            cout << "ERROR 90: Invalid choice" << endl;
            continue;
        }
        switch (choice){
            case 1:
                registerFunction();
                break;
            case 2:
                listKeys();
                break;
            case 3:
                invoke();
                break;
            case 4:
                getText();
                break;
            case 5:
                break;
        }
    }

    // cleanup open handles
    for(auto i: open_handles){
        dlclose(i);
    }
}