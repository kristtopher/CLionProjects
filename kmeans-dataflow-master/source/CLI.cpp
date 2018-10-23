#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <vector>

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

    std::vector<Node> reg_shift;
    size_t reg_shift_it = 0;

    for (size_t dimension = 0; dimension < dimensions; dimension++)
    {
        size_t reg_shift_id = Node::GetID(Node::REG);

        reg_shift.push_back({reg_shift_id, Node::REG});

        printf("    in_%" PRIu64 " -> reg_%" PRIu64 ";\n", dimension,
               reg_shift_id);

        size_t reg0_id = Node::GetID(Node::REG);
        size_t reg_last_id = Node::GetID(Node::REG);

        printf("    reg_%" PRIu64 " -> reg_%" PRIu64 ";\n", reg_shift_id,
               reg0_id);

        printf("    reg_%" PRIu64 " -> reg_%" PRIu64 ";\n", reg0_id,
               reg_last_id);

        for (size_t it = 0; it < k - 1; it++)
        {
            size_t reg_new_id = Node::GetID(Node::REG);

            printf("    reg_%" PRIu64 " -> reg_%" PRIu64 ";\n", reg_last_id,
                   reg_new_id);

            reg_last_id = reg_new_id;
        }

        inputs[dimension] = reg_last_id;
    }

    size_t reduction_depth = 0;

    for (size_t k_it = 0; k_it < k; k_it++)
    {
        queue_add_reduction.clear();
        reduction_depth = 0;

        for (size_t dimension = 0; dimension < dimensions; dimension++)
        {
            size_t in_id = reg_shift[reg_shift_it++].id;
            size_t reg_shift_id = Node::GetID(Node::REG);

            reg_shift.push_back({reg_shift_id, Node::REG});

            size_t sub_id = Node::GetID(Node::SUB);
            size_t mul_id = Node::GetID(Node::MUL);

            if (k_it != k - 1)
            {
                printf("    reg_%" PRIu64 " -> reg_%" PRIu64 ";\n", in_id,
                       reg_shift_id);

                printf("    reg_%" PRIu64 " -> sub_%" PRIu64 ";\n",
                       reg_shift_id, sub_id);
            }
            else
            {
                printf("    reg_%" PRIu64 " -> sub_%" PRIu64 ";\n", in_id,
                       sub_id);
            }

            printf("    const_%" PRIu64 "_0 -> sub_%" PRIu64 ";\n", k_it,
                   sub_id);

            printf("    sub_%" PRIu64 " -> mul_%" PRIu64 ";\n", sub_id, mul_id);

            printf("    imm_%" PRIu64 " -> sub_%" PRIu64 ";\n",
                   Node::GetID(Node::IMM), sub_id);

            printf("    sub_%" PRIu64 " -> mul_%" PRIu64 ";\n", sub_id, mul_id);

            Node node = {mul_id, Node::MUL};

            for (size_t it = k - k_it; it > 2; it--)
            {
                size_t new_reg_id = Node::GetID(Node::REG);

                printf("    %s_%" PRIu64 " -> reg_%" PRIu64 ";\n",
                       Node::GetName(node.type), node.id, new_reg_id);

                node.id = new_reg_id;
                node.type = Node::REG;
            }

            queue_add_reduction.push_back(node);
        }

        size_t queue_it = 0;
        size_t increment_depth_at = queue_add_reduction.size();

        while (queue_it < queue_add_reduction.size() - 1)
        {
            if (queue_it + 2 > increment_depth_at)
            {
                size_t reg_id = Node::GetID(Node::REG);

                printf("    %s_%" PRIu64 " -> reg_%" PRIu64 ";\n",
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

                printf("    %s_%" PRIu64 " -> %s_%" PRIu64 ";\n",
                       Node::GetName(queue_add_reduction[queue_it].type),
                       queue_add_reduction[queue_it].id,
                       Node::GetName(Node::ADD), add_id);

                printf("    %s_%" PRIu64 " -> %s_%" PRIu64 ";\n",
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

            printf("    reg_%" PRIu64 " -> reg_%" PRIu64 ";\n",
                   inputs[dimension], reg_id);

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

            printf("    %s_%" PRIu64 " -> reg_%" PRIu64 ";\n",
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

            printf("    %s_%" PRIu64 " -> %s_%" PRIu64 ";\n",
                   Node::GetName(queue_cmp_reduction[queue_it].type),
                   queue_cmp_reduction[queue_it].id, Node::GetName(Node::CMP),
                   cmp_id);

            printf("    %s_%" PRIu64 " -> %s_%" PRIu64 ";\n",
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

            printf("    reg_%" PRIu64 " -> reg_%" PRIu64 ";\n",
                   inputs[dimension], reg_id);

            inputs[dimension] = reg_id;
        }
    }

    size_t id = queue_cmp_reduction[queue_it].id;
    const char* name = Node::GetName(queue_cmp_reduction[queue_it].type);

    for (size_t k_it = 0; k_it < k; k_it++)
    {
        size_t eq_id = Node::GetID(Node::EQ);

        printf("    const_%" PRIu64 "_1 -> eq_%" PRIu64 ";\n", k_it, eq_id);
        printf("    %s_%" PRIu64 " -> eq_%" PRIu64 ";\n", name, id, eq_id);

        for (size_t dimension = 0; dimension < dimensions; dimension++)
        {
            size_t acc_id = Node::GetID(Node::ACC);

            printf("    eq_%" PRIu64 " -> acc_%" PRIu64 ";\n", eq_id, acc_id);
            printf("    reg_%" PRIu64 " -> acc_%" PRIu64 ";\n",
                   inputs[dimension], acc_id);
        }
    }

    printf("}");

    return 0;
}
