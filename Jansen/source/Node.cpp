#include "Node.h"

const char* Node::TypeName[9] = {"in", "sub", "mul", "add", "cmp",
                                 "eq", "acc", "reg", "imm"};

size_t Node::LastID[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0,
};

const char* Node::GetName(Type type)
{
    return TypeName[type];
}

size_t Node::GetID(Type type)
{
    return LastID[type]++;
}
