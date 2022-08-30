#include <iostream>
#include <string>

/// Print a newline-terminated message to the console
///
/// @param message The message to print
void printSomething(std::string message) { std::cout << message << std::endl; }

/// Use the `printSomething` function to print "Hello World"
int main() { printSomething("Hello World"); }