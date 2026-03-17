import os
import ast
import shutil

class RemoveCommentsTransformer(ast.NodeTransformer):
    def _strip_docstrings_except_first(self, node):
        if not hasattr(node, "body") or not node.body:
            return node
            
        new_body = []
        for i, stmt in enumerate(node.body):
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                is_docstring = (i == 0) and isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                if is_docstring:
                    new_body.append(stmt)
            else:
                new_body.append(stmt)
                
        node.body = new_body
        return node

    def visit_Module(self, node):
        node = self._strip_docstrings_except_first(node)
        return self.generic_visit(node)

    def visit_ClassDef(self, node):
        node = self._strip_docstrings_except_first(node)
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        node = self._strip_docstrings_except_first(node)
        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        node = self._strip_docstrings_except_first(node)
        return self.generic_visit(node)

def process_file(filepath):
    """Parses a Python file with AST, removing comments and unused strings, then unparses it."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
            
        tree = ast.parse(source)
        transformer = RemoveCommentsTransformer()
        tree = transformer.visit(tree)
        ast.fix_missing_locations(tree)
        
        clean_source = ast.unparse(tree)
        
        header = []
        for line in source.splitlines():
            if line.startswith("#!") or line.startswith("# -*- coding") or line.startswith("# coding="):
                header.append(line)
            else:
                break
                
        final_content = ""
        if header:
            final_content += "\n".join(header) + "\n"
        final_content += clean_source + "\n"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(final_content)
        return True
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def get_all_py_files(repo_path):
    py_files = []
    for root, dirs, files in os.walk(repo_path):
        if 'venv' in root or '.git' in root:
            continue
        for file in files:
            if file.endswith('.py'):
                py_files.append(os.path.join(root, file))
    return py_files

def cleanup_project(repo_path):
    print("🧹 Starting Predator Project Cleanup...")
    py_files = get_all_py_files(repo_path)
    
    # 1. Strip comments
    processed_count = 0
    for pf in py_files:
        if process_file(pf):
            processed_count += 1
    print(f"✅ Stripped comments from {processed_count} Python files.")

    # 2. Find dead files (very simple heuristic)
    contents = {}
    for pf in py_files:
        with open(pf, 'r', encoding='utf-8') as f:
            contents[pf] = f.read()
            
    dead_files = []
    for pf in py_files:
        basename = os.path.basename(pf).replace('.py', '')
        if basename in ['__init__', 'predator', 'cleanup']:
            continue
            
        is_used = False
        for current_file, content in contents.items():
            if current_file == pf:
                continue
            if basename in content:
                is_used = True
                break
                
        if not is_used:
            dead_files.append(pf)
            
    if dead_files:
        print("\n🗑️  Found unused files. Deleting:")
        for df in dead_files:
            try:
                os.remove(df)
                print(f"   - {df}")
            except Exception:
                pass
    else:
        print("\n✅ No unreferenced Python files found.")

    # 3. Delete __pycache__
    print("\n🧹 Cleaning __pycache__ directories...")
    cache_count = 0
    for root, dirs, files in os.walk(repo_path, topdown=False):
        if 'venv' in root or '.git' in root:
            continue
        for d in dirs:
            if d == '__pycache__':
                dir_path = os.path.join(root, d)
                try:
                    shutil.rmtree(dir_path)
                    cache_count += 1
                except Exception:
                    pass
    print(f"✅ Deleted {cache_count} __pycache__ directories.")
    
    print("\n🎉 Cleanup Complete! Project is ready for release.")

if __name__ == "__main__":
    import sys
    # Use current working directory if no arg provided
    repo_directory = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    cleanup_project(repo_directory)
