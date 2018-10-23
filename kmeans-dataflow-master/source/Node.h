#ifndef NODE_H
#define NODE_H

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

#endif
