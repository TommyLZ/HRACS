#include <iostream>
#include <iostream>
#include <cstring>
#include <chrono>

#include "PublicParam.h"
#include "Registration.h"
#include "Login.h"
#include "Upload.h"
#include "SingleQuery.h"
#include "BatchQuery.h"
#include "Update.h"

using namespace std;

int main()
{
    string identity = "15926254568";
    string password = "19880532Tom";
    
    sysInitial();

    auto start = std::chrono::high_resolution_clock::now();
    Registration(identity, password);
    Login(identity, password);
    Upload();
    SingleQuery();
    BatchQuery();
    Update();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "函数执行时间: " << elapsed.count() << " 秒" << std::endl;
    return 0;
}