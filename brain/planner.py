"""
brain/planner.py

A* forward-chaining planner for multi-step exploit chains.

Each exploit module should expose a PLANNER_META dict at module level:
    PLANNER_META = {
        "name":          "sudo_abuse",
        "preconditions": ["user_shell", "sudo_nopasswd"],
        "effects":       ["root_shell"],
        "cost":          1,
    }

The planner searches for the cheapest sequence of actions (exploits) that
evolves the current state to include the goal fact ('root_shell' by default).
"""
import heapq
import importlib.util
import pathlib
from utils.logger import get_logger
logger = get_logger('Planner')
_BUILTIN_ACTIONS = [{'name': 'writable_passwd', 'preconditions': ['user_shell', 'writable_passwd'], 'effects': ['root_shell'], 'cost': 1}, {'name': 'sudo_abuse', 'preconditions': ['user_shell', 'sudo_nopasswd'], 'effects': ['root_shell'], 'cost': 1}, {'name': 'cap_setuid', 'preconditions': ['user_shell', 'cap_setuid'], 'effects': ['root_shell'], 'cost': 1}, {'name': 'suid_bash', 'preconditions': ['user_shell', 'suid_bash'], 'effects': ['root_shell'], 'cost': 1}, {'name': 'suid_find', 'preconditions': ['user_shell', 'suid_find'], 'effects': ['root_shell'], 'cost': 1}, {'name': 'suid_vim', 'preconditions': ['user_shell', 'suid_vim'], 'effects': ['root_shell'], 'cost': 1}, {'name': 'suid_nmap', 'preconditions': ['user_shell', 'suid_nmap'], 'effects': ['root_shell'], 'cost': 1}, {'name': 'lxd_breakout', 'preconditions': ['user_shell', 'in_lxd_group'], 'effects': ['root_shell'], 'cost': 2}, {'name': 'docker_escape', 'preconditions': ['user_shell', 'in_docker_group'], 'effects': ['root_shell'], 'cost': 2}, {'name': 'suid_python', 'preconditions': ['user_shell', 'suid_python', 'has_python3'], 'effects': ['root_shell'], 'cost': 2}, {'name': 'pkexec_pwnkit', 'preconditions': ['user_shell', 'kernel_lt_5_13'], 'effects': ['root_shell'], 'cost': 3}, {'name': 'sudo_baron_samedit', 'preconditions': ['user_shell', 'sudo_version_lt_1_9_5'], 'effects': ['root_shell'], 'cost': 3}, {'name': 'cron_hijack', 'preconditions': ['user_shell', 'cron_writable_script'], 'effects': ['root_shell'], 'cost': 2}, {'name': 'dirtycow', 'preconditions': ['user_shell', 'kernel_lt_4_8'], 'effects': ['root_shell'], 'cost': 3}, {'name': 'dirtypipe', 'preconditions': ['user_shell', 'kernel_lt_5_16'], 'effects': ['root_shell'], 'cost': 3}, {'name': 'ld_preload', 'preconditions': ['user_shell', 'ld_preload_possible'], 'effects': ['root_shell'], 'cost': 2}, {'name': 'nfs_root_squash', 'preconditions': ['user_shell', 'nfs_no_root_squash'], 'effects': ['root_shell'], 'cost': 3}, {'name': 'always_install_elevated', 'preconditions': ['user_shell', 'always_install_elevated'], 'effects': ['root_shell'], 'cost': 2}, {'name': 'hotpotato', 'preconditions': ['user_shell', 'se_impersonate'], 'effects': ['root_shell'], 'cost': 2}, {'name': 'printspoofer', 'preconditions': ['user_shell', 'se_impersonate'], 'effects': ['root_shell'], 'cost': 2}, {'name': 'unquoted_path', 'preconditions': ['user_shell', 'unquoted_service_path'], 'effects': ['root_shell'], 'cost': 2}]

def _heuristic(state_set: frozenset, goal: str) -> int:
    """Admissible h(n): 0 if goal satisfied, 1 otherwise."""
    return 0 if goal in state_set else 1

def plan_attack(initial_state: dict, exploit_actions: list | None=None, goal: str='root_shell', max_depth: int=5, max_plans: int=3) -> list:
    """
    A* forward-chaining planner.

    Parameters
    ----------
    initial_state   : fact dict — {feature_name: bool|int}
    exploit_actions : list of PLANNER_META dicts; uses _BUILTIN_ACTIONS if None
    goal            : target fact that must become True
    max_depth       : maximum chain length (avoids infinite search)
    max_plans       : how many distinct plans to return

    Returns
    -------
    List of plans, each plan = list of exploit names in execution order.
    Empty list if no path exists within max_depth.
    """
    actions = exploit_actions or _BUILTIN_ACTIONS
    initial_set = frozenset((k for k, v in initial_state.items() if v))
    if goal in initial_set:
        return [[]]
    counter = [0]

    def push(heap, f, g, state, path):
        counter[0] += 1
        heapq.heappush(heap, (f, counter[0], g, state, path))
    heap = []
    push(heap, _heuristic(initial_set, goal), 0, initial_set, [])
    visited: dict = {}
    plans: list = []
    while heap and len(plans) < max_plans:
        f, _, g, state_set, path = heapq.heappop(heap)
        if len(path) >= max_depth:
            continue
        visit_key = (state_set, tuple(sorted(path)))
        if visit_key in visited and visited[visit_key] <= g:
            continue
        visited[visit_key] = g
        for action in actions:
            preconds = set(action.get('preconditions', []))
            if not preconds.issubset(state_set):
                continue
            new_effects = set(action.get('effects', []))
            new_state = state_set | new_effects
            new_path = path + [action['name']]
            new_g = g + action.get('cost', 1)
            new_h = _heuristic(new_state, goal)
            if goal in new_state:
                plans.append(new_path)
            else:
                push(heap, new_g + new_h, new_g, new_state, new_path)
    logger.info(f'Planner found {len(plans)} plan(s) from {len([k for k, v in initial_state.items() if v])} features.')
    return plans

def load_exploit_actions(exploit_dir: str='exploits') -> list:
    """
    Auto-discover PLANNER_META dicts from all exploit modules.
    Falls back to _BUILTIN_ACTIONS for any module that doesn't declare one.
    """
    discovered: list = []
    known_names: set = set()
    for path in pathlib.Path(exploit_dir).rglob('*.py'):
        if path.name.startswith('_'):
            continue
        try:
            spec = importlib.util.spec_from_file_location('_probe', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, 'PLANNER_META'):
                meta = mod.PLANNER_META
                if isinstance(meta, dict) and 'name' in meta:
                    discovered.append(meta)
                    known_names.add(meta['name'])
        except Exception:
            pass
    for action in _BUILTIN_ACTIONS:
        if action['name'] not in known_names:
            discovered.append(action)
    logger.info(f'Planner: {len(discovered)} actions available.')
    return discovered

def plan_to_recommendations(plan: list, confidence_base: float=0.9) -> list:
    """
    Convert a planner output (list of exploit names) into recommendation dicts
    compatible with the ExploitExecutor interface.

    Confidence decays slightly with position in the chain.
    """
    recs = []
    for i, name in enumerate(plan):
        recs.append({'name': name.replace('_', ' ').title(), 'module': name, 'type': 'manual', 'confidence': round(confidence_base * 0.95 ** i, 3), 'source': 'planner', 'reason': f'Step {i + 1} in A* attack plan'})
    return recs
