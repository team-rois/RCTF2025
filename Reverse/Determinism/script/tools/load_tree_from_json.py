import json
import collections

class TreeNode:
    """
    带 ID 和层数的二叉树节点类。
    """
    def __init__(self, node_id, val, level):
        self.id = node_id
        self.val = val
        self.level = level
        self.left = None
        self.right = None

    def __repr__(self):
        return f"TreeNode(id={self.id}, val={self.val}, level={self.level})"


def load_tree_from_json(filename):
    """
    从 JSON 文件中加载树结构及元数据。
    返回：
        root: 二叉树根节点
        nodes_dict: {id -> TreeNode}
        edges: [(parent_id, child_id), ...]
        target_sum: int
    """
    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)

    nodes_info = data.get("nodes", [])
    edges = data.get("edges", [])
    target_sum = data.get("target_sum", 0)

    # 1️⃣ 构建节点字典
    nodes_dict = {}
    for n in nodes_info:
        node = TreeNode(n["id"], n["val"], n["level"])
        nodes_dict[n["id"]] = node

    # 2️⃣ 根据 edges 构建父子关系
    for parent_id, child_id in edges:
        parent = nodes_dict.get(parent_id)
        child = nodes_dict.get(child_id)
        if parent and child:
            # 优先填左孩子
            if not parent.left:
                parent.left = child
            elif not parent.right:
                parent.right = child
            else:
                # 正常不会出现第三个孩子，但保险起见警告
                print(f"⚠️ 节点 {parent_id} 已经有两个子节点，忽略 {child_id}")

    # 3️⃣ 根节点推断：即不被任何边的 child 引用的节点
    all_ids = set(nodes_dict.keys())
    child_ids = {c for _, c in edges}
    root_ids = list(all_ids - child_ids)
    root = nodes_dict[root_ids[0]] if root_ids else None

    return root, nodes_dict, edges, target_sum


def print_tree(root):
    """
    按层打印树结构。
    """
    if not root:
        print("空树")
        return

    queue = collections.deque([(root, 0)])
    current_level = 0
    line = []

    while queue:
        node, level = queue.popleft()
        if level != current_level:
            print(f"Level {current_level}: " + "  ".join(line))
            line = []
            current_level = level
        line.append(f"[id={node.id}, val={node.val}]")
        if node.left:
            queue.append((node.left, level + 1))
        if node.right:
            queue.append((node.right, level + 1))

    if line:
        print(f"Level {current_level}: " + "  ".join(line))


if __name__ == "__main__":
    filename = "test_case_1.json"  # 你生成的JSON文件名
    root, nodes_dict, edges, target_sum = load_tree_from_json(filename)

    print("✅ 树加载成功！")
    print(f"节点总数: {len(nodes_dict)}")
    print(f"边数: {len(edges)}")
    print(f"目标和 target_sum = {target_sum}\n")

    # 打印树的层级结构
    print_tree(root)
