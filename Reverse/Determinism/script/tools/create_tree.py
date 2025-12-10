import random
import collections
import json

# 定义二叉树节点类
class TreeNode:
    """
    带ID和层数信息的二叉树节点。
    """
    # self.id_counter = 1

    def __init__(self, id_counter,val=0, left=None, right=None, level=0):
        self.id = id_counter
        # TreeNode.id_counter += 1
        self.val = val
        self.left = left
        self.right = right
        self.level = level

def generate_test_case(max_nodes=30, value_range=(-20, 20)):
    """
    生成一个测试用例，包含：
      - 一棵随机二叉树
      - 节点ID、层级信息
      - 节点之间的边表
      - 一个目标和 target_sum
    """
    if max_nodes <= 0:
        return [], [], [], 0

    min_val, max_val = value_range
    num_nodes = random.randint(1, max_nodes)

    # 初始化
    # TreeNode.id = 1  # 重置ID计数器
    id_counter = 1
    root = TreeNode(id_counter=id_counter, val=random.randint(min_val, max_val), level=0)
    queue = collections.deque([root])
    nodes_created = 1
    edges = []

    # 1. 构造随机树
    while queue and nodes_created < num_nodes:
        current_node = queue.popleft()

        id_counter += 1
        # 随机创建左节点
        if nodes_created < num_nodes and random.random() > 0.25:
            left_child = TreeNode(id_counter,random.randint(min_val, max_val), level=current_node.level + 1)
            current_node.left = left_child
            queue.append(left_child)
            edges.append((current_node.id, left_child.id))
            nodes_created += 1
        else:
            current_node.left = None
            edges.append((current_node.id, None))

        id_counter += 1
        # 随机创建右节点
        if nodes_created < num_nodes and random.random() > 0.25:
            right_child = TreeNode(id_counter,random.randint(min_val, max_val), level=current_node.level + 1)
            current_node.right = right_child
            queue.append(right_child)
            edges.append((current_node.id, right_child.id))
            nodes_created += 1
        else:
            current_node.right = None
            edges.append((current_node.id, None))

    # 2. 生成节点表
    nodes_info = []
    edges_with_null = []
    # q = collections.deque([(root, 0, None, None)])  # (node, level, parent_id, is_left)
    q = collections.deque([root])
    null_id_counter = -1

    while q:
        node = q.popleft()
        if node:
            nodes_info.append({
                "id": node.id,
                "val": node.val,
                "level": node.level
            })
            q.append(node.left)
            q.append(node.right)
        else:
            nodes_info.append({
                "id": -1,
                "val": -1,
                "level": -1
            })

    # 3. 尝试在第三层左右选择路径起点
    all_nodes = nodes_info
    level_3_nodes = [n for n in all_nodes if n["level"] >= 2]
    if not level_3_nodes:
        level_3_nodes = all_nodes  # 没有第三层则退回全体

    # 80% 概率生成真实路径和
    if random.random() < 0.8:
        start_node_info = random.choice(level_3_nodes)
        start_node = find_node_by_id(root, start_node_info["id"])

        current_path_sum = 0
        current_node = start_node
        path_length = random.randint(1, num_nodes // 3 + 1)

        for _ in range(path_length):
            if not current_node:
                break
            current_path_sum += current_node.val
            possible_next = []
            if current_node.left:
                possible_next.append(current_node.left)
            if current_node.right:
                possible_next.append(current_node.right)
            if not possible_next:
                break
            current_node = random.choice(possible_next)

        target_sum = current_path_sum
    else:
        target_sum = random.randint(min_val - 10, max_val + 10)

    # 4. 序列化树结构
    tree_list = serialize_tree(root)

    return tree_list, nodes_info, edges, target_sum

def find_node_by_id(root, target_id):
    """根据ID查找节点"""
    if not root:
        return None
    q = collections.deque([root])
    while q:
        node = q.popleft()
        if node.id == target_id:
            return node
        if node.left:
            q.append(node.left)
        if node.right:
            q.append(node.right)
    return None

def serialize_tree(root):
    """层序遍历序列化树"""
    if not root:
        return []
    result = []
    queue = collections.deque([root])
    while queue:
        node = queue.popleft()
        if node:
            result.append(node.val)
            queue.append(node.left)
            queue.append(node.right)
        else:
            result.append(None)
    while result and result[-1] is None:
        result.pop()
    return result

# --- 主程序入口 ---
if __name__ == "__main__":
    num_of_examples = 1
    print(f"--- 生成 {num_of_examples} 组测试用例 ---")

    for i in range(num_of_examples):
        tree_data, nodes_info, edges, target = generate_test_case(max_nodes=30000, value_range=(-10000, 10000))

        example = {
            "tree": tree_data,
            "nodes": nodes_info,
            "edges": edges,
            "target_sum": target
        }

        filename = f"test_case_{i + 1}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(example, f, ensure_ascii=False, indent=2)

        print(f"测试用例 {i + 1} 已保存到 {filename}")
