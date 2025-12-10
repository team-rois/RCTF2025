import random
import json

# sum number
# 6113
GLOBAL_TARGET_NAME = "g_target_sum"

valid_expr = [
    "(((flags[0] << 1) + (flags[4] >> 1) ^ flags[14])&255)  == 208",
    "hash2_16(flags[0], flags[2]) == 50141",
    "((flags[14] ^ flags[2])&255) == 84",
    "((flags[0]*(flags[7] + 3) ^ flags[16]*2)&255)== 145",
    "hash2_16(flags[0], flags[13]) == 58957",
    "(((flags[1] ^ flags[2]) + flags[16]*2 )&255) == 13",
    "(((flags[11]*3 ^ flags[1] + flags[16]) + 17 )&255) == 241",
    "((flags[10]*(flags[15] + 3) ^ flags[11]*2)&255)== 100",
    "hash2_16(flags[11], flags[2]) == 55732",
    "flags[8] ^ flags[1] == 3",
    "((flags[4]*(flags[7] + 3) ^ flags[16]*2)&255)== 37",
    "hash2_16(flags[10], flags[13]) == 5086",
    "(((flags[4] ^ flags[10]) + flags[5]*2 )&255) == 247",
    "(((flags[9]*3 ^ flags[6] + flags[2]) + 17)&255) == 113",
    "(((flags[3]*(flags[8] + 3) ^ flags[5]*2))&255) == 180",
    "hash2_16(flags[6], flags[15]) == 34907",
    "(((flags[12] << 1) + (flags[9] >> 1) ^ flags[6])&255)== 217",
    # "hash2_16(flags[0], flags[17]) == 31698",
    # "flags[17] ^ flags[18] == 9"
]

# record all valid node
valid_path = [(24, 5783),(42, -7171),(66, -1733),(106, -3415),(171, 7703),(269, -8204),(419, 2875),(635, 7495),(962, 7641),(1457, -183),(2188, -7455),(3313, 3473),(4991, 2466),(7539, -17),(11279, 2740),(16847, -5885)]
def gen_constraint(flags_count=16):
    a,b,c,d = random.sample(range(flags_count), 4)
    v = random.randint(0, 255)
    k = random.randint(-3, 3)
    t = random.random()
    
    if t < 0.25:
        return f"((flags[{a}] << 1) + (flags[{b}] >> 1) ^ flags[{c}]) & 255 == {v}"
    elif t < 0.35:
        return f"((flags[{a}] * 0xf) - (flags[{b}] * 0x8) * flags[{c}]) & 255 == {v}"
    elif t < 0.45:
        return f"(flags[{a}] + flags[{b}]) & 255 == {v}"
    elif t < 0.65:
        return f"(flags[{a}] * (flags[{b}] + {k}) ^ flags[{c}]) & 255 == {v}"
    elif t < 0.8:
        return f"(flags[{a}] * flags[{b}]) * (flags[{c}] + flags[{d}]) == {v}"
    elif t < 0.9:
        return f"((flags[{a}] += flags[{b}]) & 255) == {v}"
    else:
        h = random.randint(10000, 60000)
        return f"hash2_16(flags[{a}], flags[{b}]) == {h}"
    
def load_constraints(config_path, total_nodes):
    with open(config_path) as f:
        rules = json.load(f)

    constraints = {}
    for i in range(total_nodes):
        node = f"node_{i+1}"
        if node in rules and rules[node]:
            constraints[node] = rules[node]
        else:
            # 自动生成 2~4 条约束
            constraints[node] = [gen_constraint() for _ in range(random.randint(2, 4))]
    return constraints


def gen_code_for_node(node, constraint_expr=None):
    nid = node.get("id")
    if nid is None or nid < 0:
        return None

    val = node.get("val", 0)
    level = node.get("level", 0)

    fn_name = f"Code{nid}"
    lines = []
    lines.append(f"/* Auto-generated from nodes JSON: id={nid}, val={val}, level={level} */")
    lines.append(f"int {fn_name}(Controller* control, unsigned char flags[]) {{")
    lines.append(f"    /* node value and level (from JSON) */")
    lines.append(f"    const int value = {val};")
    lines.append(f"    const int level = {level};")
    lines.append("")
    lines.append("    /* Record-phase: if controller in RECORD state, update sum and path buffer */")
    lines.append("    if (control->state == CTL_STATE_RECORD) {")
    lines.append(f"        control->sum += value;")
    # use global target name
    lines.append(f"        if (level < 0) {{")
    lines.append("            control->check = CTL_CHECK_FAILED;")
    lines.append("            return -1;")
    lines.append("        }")
    lines.append("        if (control->path_buf_len < sizeof(control->path_buf)) {")
    lines.append("            control->path_buf[control->path_buf_len++] = value;")
    lines.append("        }")
    lines.append("    }")
    lines.append("")
    lines.append("    if (control->state == CTL_STATE_NONE) {")
    lines.append("        control->check = CTL_CHECK_NO;")
    lines.append("    }")
    lines.append("    else if (control->state == CTL_STATE_RECORD) {")
    if constraint_expr:
        # place the constraint expression here
        # wrap expression in parentheses to avoid precedence issues
        lines.append(f"        if ({constraint_expr}) {{")
        lines.append("            control->check = CTL_CHECK_PASS;")
        lines.append("        } else {")
        lines.append("            control->check = CTL_CHECK_FAILED;")
        lines.append("        }")
    else:
        # no constraint provided: mark as NoCheck (or keep as pass depending on your policy)
        lines.append("        /* no explicit constraint for this node -> mark as NoCheck */")
        lines.append("        control->check = CTL_CHECK_NO;")
    lines.append("    }")
    lines.append("")
    lines.append("    /* hardcode the last visited block id */")
    lines.append(f"    control->last_block_id = {nid};")
    lines.append("")
    lines.append("    return 0;")
    lines.append("}")

    return "\n".join(lines),fn_name


def generate(nodes, constraints):
    out = []
    out.append('#include "global_hdr.h"')
    out.append("")
    out.append("/* Auto-generated Code<id> functions */")
    out.append("")
    out.append("long long " + GLOBAL_TARGET_NAME + "= 6113;")
    for node in nodes:
        nid = node.get("id")
        if nid is None or nid < 0:
            continue
        expr = constraints.get(nid)
        func = gen_code_for_node(node, expr)
        if func:
            out.append(func)
            out.append("")  # blank line
    return "\n".join(out)


filename = "test_case_1.json"
with open(filename,'r') as fd:
    objs = json.load(fd)

nodes = objs['nodes']
code = ""
out = []
out.append('#include "global_hdr.h"')
out.append("")
out.append("/* Auto-generated Code<id> functions */")
out.append("")
# out.append("")
out.append("unsigned long long " + GLOBAL_TARGET_NAME + "= 6113;")
out.append("static __attribute__((always_inline)) inline uint32_t mix32(uint32_t x) {")
out.append("    x = (x + 0x9E3779B9u) & 0xFFFFFFFFu;")
out.append("    x = (x ^ (x >> 16)) * 0x85EBCA6Bu;")
out.append("    x &= 0xFFFFFFFFu;")
out.append("    x = (x ^ (x >> 13)) * 0xC2B2AE35u;")
out.append("    x &= 0xFFFFFFFFu;")
out.append("    x = x ^ (x >> 16);")
out.append("    return x & 0xFFFFFFFFu;")
out.append("}")

out.append("static __attribute__((always_inline)) inline uint16_t hash2_16(uint8_t a, uint8_t b) {")
out.append("    uint32_t key = ((uint32_t)(a & 0xFF) << 8) | (uint32_t)(b & 0xFF);")
out.append("    uint32_t mixed = mix32(key);")
out.append("    return (uint16_t)(mixed & 0xFFFFu);")
out.append("}   ")

announce = "void* announce[] = {"
for each_node in nodes:
    if each_node == None:
        pass
    val = each_node['val']
    block_id = each_node['id']

    # if val == 7641:
    #     print(each_node)
    # 替换目标程序
    if val == -1:
        # 这里依然要把当前的地址加入到全局数组中
        announce += "NULL,"
        pass
    else:
        # here we will try generate code
        # if each_node is in valid path
        if (block_id,val) in valid_path:
            each_expr = valid_expr.pop()
            print("popping expr " + each_expr)
            print(val)
        else:
            each_expr = gen_constraint()

        func,func_name = gen_code_for_node(each_node,each_expr)
        if func:
            announce += func_name + ","
            out.append(func)
            out.append("")

code = '\n'.join(out)
code += "\n" + announce + "};"
# print(code)
with open("code.c", 'w') as fd:
    fd.write(code)

print(valid_expr)
