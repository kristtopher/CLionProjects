from enum import Enum

class Node:

  class Type(Enum):
    REG = 0
    ADD = 1
    IMM = 2
    IN = 3
    SUB = 4
    QUAD = 5
    CMP = 6
    EQ = 7
    CONST = 8
    ACC = 9
  
  @classmethod
  def get_node(cls, node_type, graph):
    index = node_type.value
    node_id = cls.next_id[index]
    cls.next_id[index] += 1
    node = Node(node_id, node_type)
    graph[node] = []
    return node

  @classmethod
  def reduce(cls, nodes, operation, graph):
    while len(nodes) > 1:
      queue = nodes
      nodes = []
      it = 0

      while it < len(queue):

        if it + 2 <= len(queue):
          operator = cls.get_node(operation, graph)
          graph[queue[it]].append(operator)
          graph[queue[it + 1]].append(operator)
          nodes.append(operator)
          it += 2

        else:
          reg = cls.get_node(cls.Type.REG, graph)
          graph[queue[it]].append(reg)
          nodes.append(reg)
          it += 1
    
    return nodes[0]

  @classmethod
  def balance(cls, node, out, graph):
    nodes = [node]
    
    while (True):
      
      if len(nodes) * 2 < len(out):
        queue = nodes
        nodes = []
        
        for el in queue:
          regl = cls.get_node(cls.Type.REG, graph)
          regr = cls.get_node(cls.Type.REG, graph)
          graph[el].append(regl)
          graph[el].append(regr)
          nodes.append(regl)
          nodes.append(regr)

      else:
        queue = nodes
        it_queue = 0
        it_out = 0

        while it_out < len(out):

          if len(out) - it_out > len(queue) - it_queue:
            graph[queue[it_queue]].append(out[it_out])
            graph[queue[it_queue]].append(out[it_out + 1])
            it_out += 2
            
          else:
            graph[queue[it_queue]].append(out[it_out])
            it_out += 1
          
          it_queue += 1

        break

    return out
    

  @classmethod
  def delay(cls, node, n, graph):
    while n > 0:
      reg = Node.get_node(Node.Type.REG, graph)
      graph[node].append(reg)
      node = reg
      n -= 1
    return node

  @classmethod
  def print_dot(cls, graph):
    print("digraph {") 

    for k, v in graph.items():

      for i in v:
        print("    {} -> {}".format(k, i))

    print("}")
  
  next_id = [0 for x in Type]
  
  def __init__(self, node_id, node_type):
    self.id = node_id
    self.type = node_type
    
  def __str__(self):
    return "{}_{}".format(self.type.name, self.id)
