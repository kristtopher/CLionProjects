from .utils import Node
import math
from itertools import chain

def generate(k, dimensions):
  graph = {}

  inputs = [Node.get_node(Node.Type.IN, graph) for x in range(dimensions)]

  regs = [Node.get_node(Node.Type.REG, graph) for x in range(dimensions)]

  accs = [[Node.get_node(Node.Type.ACC, graph) for x in range(dimensions)]
          for y in range(k)]

  imms = [[Node.get_node(Node.Type.IMM, graph) for x in range(dimensions)]
          for y in range(k)]

  subs = [[Node.get_node(Node.Type.SUB, graph) for x in range(k)]
          for y in range(dimensions)]

  balanced_inputs = list(chain(*[Node.balance(x, [regs[it], *subs[it]], graph)
                                 for it, x in enumerate(inputs)]))

  for i, reg in enumerate(regs):
    regs[i] = Node.delay(reg, 1 + math.ceil(math.log2(dimensions)) +
                              math.ceil(math.log2(k)) + 1 +
                              (0 if k < 2 else math.ceil(math.log2(k)) - 1),
                              graph)

  subs_ordered = []

  for K, imms_k in enumerate(imms):
    subs_ordered.append([])

    for dim, imm in enumerate(imms_k):
      graph[imm].append(subs[dim][K])
      subs_ordered[K].append(subs[dim][K])

    print(*subs_ordered[K])
    
  inertias = []
  for subs_k in subs_ordered:
    to_reduce = []

    for sub in subs_k:
      quad = Node.get_node(Node.Type.QUAD, graph)
      graph[sub].append(quad)
      to_reduce.append(quad)
  
    inertias.append(Node.reduce(to_reduce, Node.Type.ADD, graph))
  
  cmp_node = Node.reduce(inertias, Node.Type.CMP, graph)

  consts = [Node.get_node(Node.Type.CONST, graph) for x in range(k)]
  eqs = [Node.get_node(Node.Type.EQ, graph) for x in range(k)]
  
  Node.balance(cmp_node, eqs, graph)

  for it, const in enumerate(consts):
    graph[const].append(eqs[it])

  for i, eq in enumerate(eqs):
    Node.balance(eq, accs[i], graph)

  accs_by_dim = [[0 for x in range(k)] for x in range(dimensions)]

  for x in range(k):
    for y in range(dimensions):
      accs_by_dim[y][x] = accs[x][y]

  for x, reg in enumerate(regs):
    Node.balance(reg, accs_by_dim[x], graph)

  Node.print_dot(graph)

  return graph
