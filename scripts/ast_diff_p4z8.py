"""AST-level delta report: integrated vega_p4z8 agent vs validated standalone.

Only the documented integration deltas may differ: the three hardening fixes
(model config error, materials path guard, atomic artifact write), the
platform v2 base64-decode wiring (_response_record + decode_b64_flags +
B64_CANDIDATE_RX), and the base64 import lift in decode_value (the standalone
already ships 5 competition rounds incl. non-SQL vectors: traversal, SSTI,
HPP, header injection, cookie forgery, registration).
"""

import ast
import sys

STANDALONE = "/home/z/my-project/work/inspect-p4z8/agent.py"
INTEGRATED = (
    "/home/z/my-project/work/main/security-agent-feature-sast-contours/"
    "vega_p4z8/agent.py"
)

EXPECTED_CHANGED_FUNCS = {
    "model",
    "safe_material_path",
    "write_artifact",
    "decode_value",
    "_response_record",
}
EXPECTED_EXTRA_FUNCS = {"decode_b64_flags"}
EXPECTED_CONST_DELTAS = {"B64_CANDIDATE_RX"}


def load(path):
    with open(path, encoding="utf-8") as stream:
        return ast.parse(stream.read())


def top_level(tree):
    funcs, consts = {}, {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs[node.name] = node
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            consts[node.targets[0].id] = node
    return funcs, consts


def main():
    sa, ia = load(STANDALONE), load(INTEGRATED)
    sa_funcs, sa_consts = top_level(sa)
    ia_funcs, ia_consts = top_level(ia)
    problems = []
    for name, node in sa_funcs.items():
        if name not in ia_funcs:
            problems.append("MISSING function: " + name)
        elif (
            ast.dump(node) != ast.dump(ia_funcs[name])
            and name not in EXPECTED_CHANGED_FUNCS
        ):
            problems.append("UNEXPECTED function change: " + name)
    for name in ia_funcs:
        if name not in sa_funcs and name not in EXPECTED_EXTRA_FUNCS:
            problems.append("UNEXPECTED extra function: " + name)
    for name, node in sa_consts.items():
        if name not in ia_consts:
            problems.append("MISSING constant: " + name)
        elif (
            ast.dump(node) != ast.dump(ia_consts[name])
            and name not in EXPECTED_CONST_DELTAS
        ):
            problems.append("UNEXPECTED constant change: " + name)
    for name in ia_consts:
        if name not in sa_consts and name not in EXPECTED_CONST_DELTAS:
            problems.append("UNEXPECTED extra constant: " + name)
    if problems:
        print("AST DELTA PROBLEMS:")
        for item in problems:
            print(" -", item)
        sys.exit(1)
    print(
        "AST delta matches expectations: changed=%s extra_funcs=%s const_deltas=%s"
        % (
            sorted(EXPECTED_CHANGED_FUNCS),
            sorted(EXPECTED_EXTRA_FUNCS),
            sorted(EXPECTED_CONST_DELTAS),
        )
    )


if __name__ == "__main__":
    main()
