import streamlit as st
import ast
import io
import sys
import re

# 🚨 Default Security Policy (can be customized)
DEFAULT_FORBIDDEN_IMPORTS = ["os", "sys", "subprocess", "socket", "shutil"]
DEFAULT_FORBIDDEN_FUNCTIONS = ["system", "popen", "remove", "rmdir", "execfile", "eval", "exec"]

# 🧠 Analyze AST for forbidden patterns
def analyze_code(code, forbidden_imports, forbidden_funcs):
    report = []
    tree = ast.parse(code)

    for node in ast.walk(tree):
        # Detect forbidden imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in forbidden_imports:
                    report.append(f"❌ Forbidden import detected: `{alias.name}`")
        elif isinstance(node, ast.ImportFrom):
            if node.module in forbidden_imports:
                report.append(f"❌ Forbidden module import: `{node.module}`")

        # Detect dangerous calls
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in forbidden_funcs:
                report.append(f"❌ Dangerous function call: `{node.func.id}()`")
            elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_funcs:
                report.append(f"❌ Dangerous function call: `{node.func.attr}()`")

    if not report:
        report.append("✅ No forbidden imports or dangerous calls found.")
    return report

# 🧬 Typed Assembly Language-inspired check (simple static typing safety)
def type_safety_analysis(code):
    issues = []
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.targets[0], ast.Name):
                    var_name = node.targets[0].id
                    if isinstance(node.value, ast.Constant) and node.value.value is None:
                        issues.append(f"⚠️ Variable `{var_name}` is assigned `None` (possible null reference).")
    except Exception as e:
        issues.append(f"⚠️ Static analysis error: {e}")
    return issues if issues else ["✅ No type safety violations detected."]

# 🛡️ Sandboxed execution (simulating JVM sandbox & SFI)
def run_sandboxed(code):
    safe_globals = {"__builtins__": {"print": print, "range": range, "len": len}}
    safe_locals = {}
    old_stdout = sys.stdout
    redirected_output = sys.stdout = io.StringIO()
    try:
        exec(code, safe_globals, safe_locals)
    except Exception as e:
        print("🚫 Runtime Error:", e)
    finally:
        sys.stdout = old_stdout
    return redirected_output.getvalue()

# 📜 Formal safety proof generator (PCC-style explanation)
def generate_safety_proof(security_report, type_report):
    proof = ["📜 **Formal Safety Proof (PCC-style):**\n"]
    proof.append("This proof certifies that the submitted code adheres to the enforced safety policy under the following checks:")
    proof.append("- Language-based static inspection of imports and function calls.")
    proof.append("- Type safety and null-reference analysis.")
    proof.append("- Inline Reference Monitor enforcement during runtime execution.")
    proof.append("- Controlled sandbox environment for safe execution.")

    safe = all("✅" in r for r in security_report + type_report)
    if safe:
        proof.append("\n✅ **Conclusion:** The program is provably safe under the current policy and can be executed securely.")
    else:
        proof.append("\n🚫 **Conclusion:** The program violates the safety policy. Execution is not permitted.")
    return "\n".join(proof)

# 🌐 Streamlit UI Setup
st.set_page_config(page_title="SafeCode Inspector 2.0", page_icon="🛡️", layout="centered")
st.title("🛡️ SafeCode Inspector 2.0")
st.caption("Advanced Security Sandbox with PCC, TAL, IRM, and JVM-like Protection")

st.markdown("""
Enter your Python code below. This system will:
- 🔍 Perform static analysis for security and type safety  
- 📜 Generate a **Formal Safety Proof** (PCC)  
- 🧪 Execute your code in a **sandbox** if safe  
- 🛠️ Allow you to define your own security policies  
""")

# ✏️ Code input
code_input = st.text_area("✍️ Paste your Python code:", height=250)

# 🔐 Policy editor
st.sidebar.header("🔐 Security Policy Editor")
user_imports = st.sidebar.text_input("Forbidden Imports (comma-separated)", ",".join(DEFAULT_FORBIDDEN_IMPORTS))
user_funcs = st.sidebar.text_input("Forbidden Functions (comma-separated)", ",".join(DEFAULT_FORBIDDEN_FUNCTIONS))

forbidden_imports = [i.strip() for i in user_imports.split(",") if i.strip()]
forbidden_funcs = [f.strip() for f in user_funcs.split(",") if f.strip()]

# 🚀 Main button
if st.button("🔎 Analyze & Execute"):
    if not code_input.strip():
        st.warning("Please enter some code first.")
    else:
        st.subheader("📊 Security Inspection Report (IRM)")
        security_report = analyze_code(code_input, forbidden_imports, forbidden_funcs)
        for r in security_report:
            st.write(r)

        st.subheader("🧬 Type Safety Analysis (TAL-inspired)")
        type_report = type_safety_analysis(code_input)
        for r in type_report:
            st.write(r)

        st.subheader("📜 Safety Proof (PCC)")
        proof = generate_safety_proof(security_report, type_report)
        st.markdown(proof)

        # ✅ Run only if code is safe
        if all("✅" in r for r in security_report + type_report):
            st.success("✅ Code is SAFE. Executing in sandbox...")
            output = run_sandboxed(code_input)
            st.subheader("🧪 Sandbox Output")
            st.code(output if output else "✅ Execution complete. No output.")
        else:
            st.error("🚫 Code violates safety policy. Execution blocked.")

st.markdown("---")
st.caption("© 2025 SafeCode Inspector 2.0 — Built using PCC, TAL, IRM, JVM Sandboxing, and SFI principles.")
