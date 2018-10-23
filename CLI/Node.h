//
// Created by kristtopher on 14/05/18.
//

#ifndef CLI_NODE_H
#define CLI_NODE_H
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <vector>
//using namespace std;
class Node
{
    static const char* TypeName[9];

    static size_t LastID[9];

public:
    enum Type
    {
        IN,
        SUB,
        MUL,
        ADD,
        CMP,
        EQ,
        ACC,
        REG,
        IMM,
    };

    size_t id;
    Type type;

    static const char* GetName(Type type);

    static size_t GetID(Type type);
};
#endif //CLI_NODE_H
