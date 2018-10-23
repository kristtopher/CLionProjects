

#include "Node.h"


int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <k> <dimensions>\n", argv[0]);
        return 1;
    }

    size_t k = strtoull(argv[1], NULL, 10);
    size_t dimensions = strtoull(argv[2], NULL, 10);

    for (size_t dimension = 0; dimension < dimensions; dimension++)
    {
        Node::GetID(Node::IN);
    }

    std::vector<Node> queue_add_reduction;
    std::vector<Node> queue_cmp_reduction;

    printf("digraph {\n");

    std::vector<size_t> inputs;
    inputs.resize(dimensions);

    for (size_t dimension = 0; dimension < dimensions; dimension++)
    {
        size_t reg0_id = Node::GetID(Node::REG);
        size_t reg1_id = Node::GetID(Node::REG);

        printf("    in%" PRIu64 " -> reg%" PRIu64 ";\n", dimension, reg0_id);

        printf("    reg%" PRIu64 " -> reg%" PRIu64 ";\n", reg0_id, reg1_id);

        inputs[dimension] = reg1_id;
    }

    size_t reduction_depth = 0;

    for (size_t k_it = 0; k_it < k; k_it++)
    {
        queue_add_reduction.clear();
        reduction_depth = 0;

        for (size_t dimension = 0; dimension < dimensions; dimension++)
        {
            size_t in_id = dimension;
            size_t sub_id = Node::GetID(Node::SUB);
            size_t mul_id = Node::GetID(Node::MUL);

            printf("    in%" PRIu64 " -> sub%" PRIu64 ";\n", in_id, sub_id);

            printf("    sub%" PRIu64 " -> mul%" PRIu64 ";\n", sub_id, mul_id);

            printf("    imm%" PRIu64 " -> sub%" PRIu64 ";\n",
                   Node::GetID(Node::IMM), sub_id);

            printf("    sub%" PRIu64 " -> mul%" PRIu64 ";\n", sub_id, mul_id);

            queue_add_reduction.push_back({mul_id, Node::MUL});
        }

        size_t queue_it = 0;
        size_t increment_depth_at = queue_add_reduction.size();

        while (queue_it < queue_add_reduction.size() - 1)
        {
            if (queue_it + 2 > increment_depth_at)
            {
                size_t reg_id = Node::GetID(Node::REG);

                printf("    %s%" PRIu64 " -> reg%" PRIu64 ";\n",
                       Node::GetName(queue_add_reduction[queue_it].type),
                       queue_add_reduction[queue_it].id, reg_id);

                queue_add_reduction.push_back({reg_id, Node::REG});

                increment_depth_at = queue_add_reduction.size();
                reduction_depth++;

                queue_it += 1;
            }
            else
            {
                size_t add_id = Node::GetID(Node::ADD);

                printf("    %s%" PRIu64 " -> %s%" PRIu64 ";\n",
                       Node::GetName(queue_add_reduction[queue_it].type),
                       queue_add_reduction[queue_it].id,
                       Node::GetName(Node::ADD), add_id);

                printf("    %s%" PRIu64 " -> %s%" PRIu64 ";\n",
                       Node::GetName(queue_add_reduction[queue_it + 1].type),
                       queue_add_reduction[queue_it + 1].id,
                       Node::GetName(Node::ADD), add_id);

                queue_add_reduction.push_back({add_id, Node::ADD});

                if (queue_it + 2 == increment_depth_at)
                {
                    increment_depth_at = queue_add_reduction.size();
                    reduction_depth++;
                }

                queue_it += 2;
            }
        }

        queue_cmp_reduction.push_back(queue_add_reduction[queue_it]);
    }

    for (size_t depth = 0; depth < reduction_depth; depth++)
    {
        for (size_t dimension = 0; dimension < dimensions; dimension++)
        {
            size_t reg_id = Node::GetID(Node::REG);

            printf("    reg%" PRIu64 " -> reg%" PRIu64 ";\n", inputs[dimension],
                   reg_id);

            inputs[dimension] = reg_id;
        }
    }

    size_t queue_it = 0;
    size_t increment_depth_at = queue_cmp_reduction.size();
    reduction_depth = 0;

    while (queue_it < queue_cmp_reduction.size() - 1)
    {
        if (queue_it + 2 > increment_depth_at)
        {
            size_t reg_id = Node::GetID(Node::REG);

            printf("    %s%" PRIu64 " -> reg%" PRIu64 ";\n",
                   Node::GetName(queue_cmp_reduction[queue_it].type),
                   queue_cmp_reduction[queue_it].id, reg_id);

            queue_cmp_reduction.push_back({reg_id, Node::REG});

            increment_depth_at = queue_cmp_reduction.size();
            reduction_depth++;

            queue_it += 1;
        }
        else
        {
            size_t cmp_id = Node::GetID(Node::CMP);

            printf("    %s%" PRIu64 " -> %s%" PRIu64 ";\n",
                   Node::GetName(queue_cmp_reduction[queue_it].type),
                   queue_cmp_reduction[queue_it].id, Node::GetName(Node::CMP),
                   cmp_id);

            printf("    %s%" PRIu64 " -> %s%" PRIu64 ";\n",
                   Node::GetName(queue_cmp_reduction[queue_it + 1].type),
                   queue_cmp_reduction[queue_it + 1].id,
                   Node::GetName(Node::CMP), cmp_id);

            queue_cmp_reduction.push_back({cmp_id, Node::CMP});

            if (queue_it + 2 == increment_depth_at)
            {
                increment_depth_at = queue_cmp_reduction.size();
                reduction_depth++;
            }

            queue_it += 2;
        }
    }

    for (size_t depth = 0; depth <= reduction_depth; depth++)
    {
        for (size_t dimension = 0; dimension < dimensions; dimension++)
        {
            size_t reg_id = Node::GetID(Node::REG);

            printf("    reg%" PRIu64 " -> reg%" PRIu64 ";\n", inputs[dimension],
                   reg_id);

            inputs[dimension] = reg_id;
        }
    }

    size_t id = queue_cmp_reduction[queue_it].id;
    const char* name = Node::GetName(queue_cmp_reduction[queue_it].type);

    for (size_t k_it = 0; k_it < k; k_it++)
    {
        size_t eq_id = Node::GetID(Node::EQ);

        printf("    imm%" PRIu64 " -> eq%" PRIu64 ";\n", Node::GetID(Node::IMM),
               eq_id);
        printf("    %s%" PRIu64 " -> eq%" PRIu64 ";\n", name, id, eq_id);

        for (size_t dimension = 0; dimension < dimensions; dimension++)
        {
            size_t acc_id = Node::GetID(Node::ACC);

            printf("    eq%" PRIu64 " -> acc%" PRIu64 ";\n", eq_id, acc_id);
            printf("    reg%" PRIu64 " -> acc%" PRIu64 ";\n", inputs[dimension],
                   acc_id);
        }
    }

    printf("}");

    return 0;
}
