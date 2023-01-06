#include <iostream>
#include "menu.h"

void menu(std::string current_text){
    using namespace std;
    cout << "Main Menu" << endl;
    cout << " [1] -- Register a new function"<< endl;
    cout << " [2] -- List registered functions"<< endl;
    cout << " [3] -- Invoke a function"<< endl;
    cout << " [4] -- Provide some text" << endl;
    cout << " [5] -- Exit" << endl;
    cout << "(current text: \"" << current_text << "\")" << endl;
    cout << ":>" << endl;
}