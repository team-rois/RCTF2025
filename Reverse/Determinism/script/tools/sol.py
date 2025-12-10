from typing import List, Optional

# 二叉树节点定义（保持一致）
class TreeNode:
    def __init__(self, val=0, id=-1,  left=None, right=None):
        self.id = id
        self.val = val
        self.left = left
        self.right = right


def print_node(nodes: List[TreeNode]):

    for each in nodes:
        print((each.id,each.val),end=',')

def find_paths(root: Optional[TreeNode], target_sum: int) -> List[List[TreeNode]]:
    """
    返回所有从任意节点开始、向下延伸、节点值之和等于 target_sum 的路径。
    """
    all_paths = []

    def dfs_from(node: Optional[TreeNode], target: int, current_path: List[TreeNode]):
        """
        从当前节点向下搜索路径。
        """
        if not node:
            return
        
        current_path.append(node)

        # 计算当前路径末尾开始的连续子路径之和
        current_sum = 0
        # 从后往前遍历，检查所有后缀是否等于 target
        for i in range(len(current_path) - 1, -1, -1):
            current_sum += current_path[i].val
            if current_sum == target:
                # 复制当前满足条件的路径后缀
                all_paths.append(current_path[i:].copy())

        # 递归左右子树
        dfs_from(node.left, target, current_path)
        dfs_from(node.right, target, current_path)

        # 回溯
        current_path.pop()

    dfs_from(root, target_sum, [])
    return all_paths


def find_target_path(root, target_id):
    """
    从root出发，找到目标节点target_id的路径。
    返回字符串，例如 '0101' （0=左, 1=右）
    """
    path = []
    path_out = []

    def dfs(node):
        if not node:
            return False
        if node.id == target_id:
            return True
        # 尝试左子树
        path.append('0')
        path_out.append(node.left)
        if dfs(node.left):
            return True
        path.pop()
        path_out.pop()

        # 尝试右子树
        path.append('1')
        path_out.append(node.right)
        if dfs(node.right):
            return True
        path.pop()
        path_out.pop()

        return False

    path_out.append(root)
    found = dfs(root)
    if found:
        print([(node.id,node.val) for node in path_out])
        return ''.join(path)
    else:
        return None

# --- 下面演示如何读取并计算 ---
if __name__ == "__main__":
    import json
    from collections import deque

    # === 反序列化函数（保持与你之前一致） ===
    def deserialize_tree(nodes):
        if not nodes:
            return None
        
        root = TreeNode(nodes[0])
        queue = deque([root])
        i = 1
        while queue and i < len(nodes):
            current = queue.popleft()
            # 左
            if i < len(nodes) and nodes[i] is not None:
                current.left = TreeNode(nodes[i])
                queue.append(current.left)
            i += 1
            # 右
            if i < len(nodes) and nodes[i] is not None:
                current.right = TreeNode(nodes[i])
                queue.append(current.right)
            i += 1
        return root
    
    def deserialize_node(nodes):
        if not nodes:
            return None
        
        print(nodes[0])
        root = TreeNode(nodes[0]['val'], nodes[0]['id'])
        queue = deque([root])
        i = 1
        idx = 100
        while queue and i < len(nodes):
            
            current = queue.popleft()
            # 左
            if i < len(nodes) and nodes[i] is not None and nodes[i]['id'] != -1:
                current.left = TreeNode(nodes[i]['val'], nodes[i]['id'])
                queue.append(current.left)
            i += 1
            # 右
            if i < len(nodes) and nodes[i] is not None and nodes[i]['id'] != -1:
                current.right = TreeNode(nodes[i]['val'], nodes[i]['id'])
                queue.append(current.right)
            if idx > 0:
                print("current node:{}".format(current.id))
                if current.left != None:
                    print("left child node:{}".format(current.left.id))
                if current.right != None:
                    print("right child node:{}".format(current.right.id))
            i += 1
            idx -= 1
        return root

    # === 从磁盘读取测试用例 ===
    filename = "test_case_1.json"
    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)
    tree_data = data["tree"]
    node_data = data["nodes"]
    target_sum = data["target_sum"]

    # === 构造树并求解 ===
    root = deserialize_tree(tree_data)
    root = deserialize_node(node_data)
    paths = find_paths(root, target_sum)

    print(f"Target Sum = {target_sum}")
    print(f"共找到 {len(paths)} 条路径：")
    paths = sorted(paths, key=len,reverse=True)
    for p in paths[:10]:  # 只显示前 10 条，防止太多
        print_node(p)
        print("")

    print(find_target_path(root, 16847))
