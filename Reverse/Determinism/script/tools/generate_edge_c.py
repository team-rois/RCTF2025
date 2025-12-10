import json
from textwrap import indent


filename = "test_case_1.json"

with open(filename, 'r') as fd:
    # content = fd.read()
    obj = json.load(fd)

edges = obj['edges']


# 把你的 edges 数据粘到这里（或者读自文件）
# edges = [
#     [1, 2],
#     [1, 3],
#     [2, None],
#     [2, 5],
#     [3, 6],
#     [3, 7],
#     [5, 8],
#     [5, 9],
#     [6, 10],
#     [6, 11],
#     [7, None],
#     [7, 13],
#     [8, 14],
#     [8, 15],
#     [9, 16],
#     [9, 17],
#     [10, None],
#     [10, None],
#     [11, 20],
#     [11, 21],
#     [13, 22],
#     [13, 23],
#     [14, 24],
#     [14, 25],
#     [15, 26],
#     [15, 27],
#     [16, 28],
#     [16, 29],
#     [17, 30],
#     [17, None]
# ]

# ---------- 将 edges 聚合为 per-source children 列表 ----------
# 聚合策略（稳健版）：
# - group children by source id, in appearance order
# - take at most two children per source: first->left, second->right
from collections import OrderedDict

groups = OrderedDict()
for pair in edges:
    if not isinstance(pair, (list, tuple)) or len(pair) < 2:
        continue
    src = pair[0]
    dst = pair[1]
    if src not in groups:
        groups[src] = []
    # append dst even if None; we'll handle None -> -1 later
    groups[src].append(dst)

# 限制为最多两个 child，并记录 if more existed
for src, childs in groups.items():
    if len(childs) > 2:
        # trim extras but keep note (we'll comment it)
        groups[src] = childs[:2]

# ---------- 生成 C 函数（Edge0, Edge1, ...） ----------
# We'll create mapping: Edge index -> source id

edges_func_array = "void* g_edges[] = {"
edge_funcs = []
last_src = 1
edge_count = 0
for idx, (src, childs) in enumerate(groups.items()):
    if idx % 10000 == 0:
        print(idx)
    left = childs[0] if len(childs) >= 1 else None
    right = childs[1] if len(childs) >= 2 else None

    # convert None to -1, otherwise keep integer
    left_val = -1 if left is None else int(left)
    right_val = -1 if right is None else int(right)

    # build C function string
    func_name = f"Edge{src}"
    func_comment = f"/* auto-generated from source id {src} */"

    c_lines = []
    c_lines.append(f"int {func_name}(Controller* control, int current_block_id, uint8_t s) {{")
    # state handling: interpret bit0 (s & 1) != 0 as 'need record'
    c_lines.append("    // s bit0: record flag; bit1: direction (0=left,1=right)")
    c_lines.append("    // Note: make sure (s & 1) and (s & 2) are parenthesized in comparisons.")
    c_lines.append("    int need_record = ((s & 1) != 0);")
    c_lines.append("    if (need_record) {")
    c_lines.append("        if (control->state == CTL_STATE_NONE) {")
    c_lines.append("            control->state = CTL_STATE_RECORD;")
    c_lines.append("        }")
    c_lines.append("    } else {")
    c_lines.append("        if (control->state == CTL_STATE_RECORD) {")
    c_lines.append("            control->state = CTL_STATE_FINISH;")
    c_lines.append("            return -1; // reached end-of-record sequence")
    c_lines.append("        }")
    c_lines.append("    }")
    c_lines.append("")
    c_lines.append("    // next_block_id: { left, right }")
    c_lines.append(f"    int next_block_id[2] = {{{left_val}, {right_val}}};")

    c_lines.append("    if (next_block_id[0] == -1 && next_block_id[1] == -1) {")
    c_lines.append("        control->state = CTL_STATE_FINISH;")
    c_lines.append("        return -1;")
    c_lines.append("    }")
    c_lines.append("")
    c_lines.append("    int32_t block_id = -1;")
    c_lines.append("    int go_right = ((s & 2) != 0);")
    c_lines.append("    if (!go_right) {")
    c_lines.append("        // go left")
    c_lines.append("        block_id = next_block_id[0];")
    c_lines.append("    } else {")
    c_lines.append("        // go right")
    c_lines.append("        block_id = next_block_id[1];")
    c_lines.append("    }")
    c_lines.append("")
    c_lines.append("    if (block_id == -1) {")
    c_lines.append("        control->state = CTL_STATE_FINISH;")
    c_lines.append("        return -1;")
    c_lines.append("    }")
    c_lines.append("    control->last_block_id = block_id;")
    c_lines.append("    control->step_index++;")
    c_lines.append("    return block_id;")
    c_lines.append("}")

    # comment about trimmed children
    extra_note = ""
    # original_child_count = len([p for p in edges if p[0] == src])
    # if original_child_count > 2:
    #     extra_note = f"/* NOTE: source {src} had {original_child_count} children in input; trimmed to first two. */"

    func_text = "\n".join([func_comment, extra_note, *c_lines])
    edge_count += 1
    # if the src != idx, that's mean there is empty edge, we should append it 
    if last_src != 1:
        for i in range(src-last_src-1):
            # print(src)
            # print(src-last_src)
            edge_count += 1
            edges_func_array += "NULL,"
    last_src = src
    edges_func_array += func_name + ","
    edge_funcs.append(func_text)
    print(edge_count)

# ---------- 输出所有函数 ----------
output = []
output.append("/* ===== auto-generated Edge functions ===== */")
output.append("/* Required controller type and enum must be declared elsewhere: */")
output.append("/* typedef enum { CTL_STATE_NONE=0, CTL_STATE_RECORD, CTL_STATE_FINISH } ctl_state_t; */")
output.append("/* typedef struct { ctl_state_t state; int last_block_id; int step_index; uint8_t path_buf[...]; ... } Controller; */")
output.append("")
output.append("#include<stdio.h>")
output.append("#include<stdlib.h>")
output.append("#include<string.h>")
output.append("#include\"global_hdr.h\"")
output.append("")
output.append("")
output.append("")
for f in edge_funcs:
    output.append(f)
    output.append("\n")  # blank line between funcs

edges_func_array += "};"
output.append(edges_func_array)
generated_code = "\n".join(output)

# print(generated_code)

with open("edge.c",'w') as fd:
    fd.write(generated_code)