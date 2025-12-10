import re

def translate_expr(expr: str) -> str:
    """
    将形如 ((flag[0] << 1) + LShR(flag[4], 1) ^ flag[14]) & 255==208
    翻译为 s.add(((flag[0] << 1) + z3.LShR(flag[4], 1) ^ flag[14]) & 0xff == 208)
    """
    expr = expr.strip()

    # 统一 == 两边的空格
    expr = expr.replace("==", " == ")
    expr = expr.replace("flag", "flags")

    # 将 LShR 转为 z3.LShR
    # expr = expr.replace("LShR", "z3.LShR")

    # 将 & 255 改为 & 0xff （更清晰）
    # expr = re.sub(r"&\s*255\b", "& 0xff", expr)
    expr = expr.replace("& 255",")")
    expr = "low(" + expr

    # 自动在前面加上 s.add(...)
    return f"s.add({expr})"


if __name__ == "__main__":
    # 示例输入，可以替换为你自己的
    with open("dump_temp.txt",'r') as fd:
        content = fd.read()

    expressions = content.split("\n")
    for e in expressions:
        print(translate_expr(e))
