"""
brain/knowledge_graph.py

Exploit Knowledge Graph backed by networkx.DiGraph with JSON serialisation.

Node types:
  Exploit        — executable module with preconditions/effects/stats
  SystemFeature  — a boolean/numeric fact about the target
  Technique      — abstract category (suid_abuse, kernel_exploit, ...)

Edge types:
  requires   — Exploit → SystemFeature  (must be True before running)
  enables    — Exploit → SystemFeature  (becomes True on success)
  chains_to  — Exploit → Exploit        (unlocks another exploit)
  belongs_to — Exploit → Technique
"""
import json
import os
from utils.logger import get_logger
logger = get_logger('KnowledgeGraph')
try:
    import networkx as nx
    _NX = True
except ImportError:
    logger.warning('networkx not installed — KnowledgeGraph will use dict fallback.')
    _NX = False
_DEFAULT_EXPLOITS = [('writable_passwd', ['user_shell', 'writable_passwd'], ['root_shell'], 'filesystem', 1), ('sudo_abuse', ['user_shell', 'sudo_nopasswd'], ['root_shell'], 'sudo_abuse', 1), ('cap_setuid', ['user_shell', 'cap_setuid'], ['root_shell'], 'capability', 1), ('suid_bash', ['user_shell', 'suid_bash'], ['root_shell'], 'suid_abuse', 1), ('suid_find', ['user_shell', 'suid_find'], ['root_shell'], 'suid_abuse', 1), ('suid_vim', ['user_shell', 'suid_vim'], ['root_shell'], 'suid_abuse', 1), ('suid_nmap', ['user_shell', 'suid_nmap'], ['root_shell'], 'suid_abuse', 1), ('suid_python', ['user_shell', 'suid_python'], ['root_shell'], 'suid_abuse', 2), ('lxd_breakout', ['user_shell', 'in_lxd_group'], ['root_shell'], 'container', 2), ('docker_escape', ['user_shell', 'in_docker_group'], ['root_shell'], 'container', 2), ('pkexec_pwnkit', ['user_shell', 'kernel_lt_5_13'], ['root_shell'], 'kernel_cve', 3), ('sudo_baron_samedit', ['user_shell', 'sudo_version_lt_1_9_5'], ['root_shell'], 'sudo_cve', 3), ('dirtycow', ['user_shell', 'kernel_lt_4_8'], ['root_shell'], 'kernel_cve', 4), ('dirtypipe', ['user_shell', 'kernel_lt_5_16'], ['root_shell'], 'kernel_cve', 4), ('cron_hijack', ['user_shell', 'cron_writable_script'], ['root_shell'], 'cron', 2), ('ld_preload', ['user_shell', 'ld_preload_possible'], ['root_shell'], 'env_abuse', 2), ('nfs_root_squash', ['user_shell', 'nfs_no_root_squash'], ['root_shell'], 'nfs', 3), ('always_install_elevated', ['user_shell', 'always_install_elevated'], ['root_shell'], 'registry', 2), ('hotpotato', ['user_shell', 'se_impersonate'], ['root_shell'], 'token', 2), ('printspoofer', ['user_shell', 'se_impersonate'], ['root_shell'], 'token', 2), ('unquoted_path', ['user_shell', 'unquoted_service_path'], ['root_shell'], 'service', 2)]

class ExploitKnowledgeGraph:
    """
    Directed graph of exploits, system features, and techniques.

    Falls back to a pure-dict implementation when networkx is not available.
    """

    def __init__(self, graph_path: str='brain/data/exploit_graph.json'):
        self.graph_path = graph_path
        if _NX:
            self.G = nx.DiGraph()
        else:
            self._nodes: dict = {}
            self._edges: list = []
        self._load()

    def _load(self):
        if os.path.exists(self.graph_path):
            try:
                with open(self.graph_path) as f:
                    data = json.load(f)
                self._from_dict(data)
                n = len(self._node_ids())
                e = len(self._edge_list())
                logger.info(f'Knowledge graph loaded: {n} nodes, {e} edges.')
                return
            except Exception as ex:
                logger.warning(f'Could not load graph ({ex}). Seeding defaults.')
        self._seed_defaults()
        self.save()

    def save(self):
        os.makedirs(os.path.dirname(self.graph_path), exist_ok=True)
        with open(self.graph_path, 'w') as f:
            json.dump(self._to_dict(), f, indent=2)

    def _node_ids(self) -> list:
        if _NX:
            return list(self.G.nodes)
        return list(self._nodes.keys())

    def _edge_list(self) -> list:
        if _NX:
            return [(u, v, dict(self.G[u][v])) for u, v in self.G.edges]
        return self._edges

    def _get_node(self, node_id: str) -> dict:
        if _NX:
            return dict(self.G.nodes.get(node_id, {}))
        return dict(self._nodes.get(node_id, {}))

    def _set_node(self, node_id: str, attrs: dict):
        if _NX:
            if not self.G.has_node(node_id):
                self.G.add_node(node_id)
            self.G.nodes[node_id].update(attrs)
        else:
            self._nodes[node_id] = attrs

    def _add_edge(self, src: str, dst: str, etype: str):
        if _NX:
            self.G.add_edge(src, dst, type=etype)
        else:
            self._edges.append({'src': src, 'dst': dst, 'type': etype})

    def _out_edges(self, node_id: str, etype: str) -> list:
        if _NX:
            return [dst for _, dst, d in self.G.out_edges(node_id, data=True) if d.get('type') == etype]
        return [e['dst'] for e in self._edges if e['src'] == node_id and e['type'] == etype]

    def _to_dict(self) -> dict:
        nodes = {}
        for nid in self._node_ids():
            nodes[nid] = self._get_node(nid)
        edges = [{'src': u, 'dst': v, 'type': d.get('type', '')} for u, v, d in self._edge_list()] if _NX else self._edges
        return {'nodes': nodes, 'edges': edges}

    def _from_dict(self, data: dict):
        if _NX:
            self.G.clear()
        else:
            self._nodes = {}
            self._edges = []
        for nid, attrs in data.get('nodes', {}).items():
            self._set_node(nid, attrs)
        for e in data.get('edges', []):
            self._add_edge(e['src'], e['dst'], e['type'])

    def _seed_defaults(self):
        for feat in ['user_shell', 'root_shell']:
            self._set_node(feat, {'type': 'SystemFeature'})
        for name, preconds, effects, technique, risk in _DEFAULT_EXPLOITS:
            self.add_exploit(name, f'exploits/{technique}/{name}.py', preconds, effects, technique=technique, risk=risk)

    def add_exploit(self, name: str, module_path: str, preconditions: list, effects: list, technique: str='user_defined', success_count: int=0, failure_count: int=0, risk: int=2):
        """Register or update an exploit node."""
        self._set_node(name, {'type': 'Exploit', 'module': module_path, 'technique': technique, 'dependencies': preconditions, 'effects': effects, 'success_count': success_count, 'failure_count': failure_count, 'risk': risk})
        tech_node = f'technique:{technique}'
        self._set_node(tech_node, {'type': 'Technique'})
        self._add_edge(name, tech_node, 'belongs_to')
        for p in preconditions:
            if not self._get_node(p):
                self._set_node(p, {'type': 'SystemFeature'})
            self._add_edge(name, p, 'requires')
        for e in effects:
            if not self._get_node(e):
                self._set_node(e, {'type': 'SystemFeature'})
            self._add_edge(name, e, 'enables')
        self.save()

    def get_preconditions(self, exploit_name: str) -> list:
        return self._out_edges(exploit_name, 'requires')

    def get_effects(self, exploit_name: str) -> list:
        return self._out_edges(exploit_name, 'enables')

    def record_outcome(self, exploit_name: str, success: bool):
        """Update success/failure counts on the exploit node."""
        node = self._get_node(exploit_name)
        if not node:
            return
        key = 'success_count' if success else 'failure_count'
        node[key] = node.get(key, 0) + 1
        self._set_node(exploit_name, node)
        self.save()

    def filter_by_preconditions(self, candidates: list, known_features: dict) -> list:
        """
        Sort candidates by fraction of met preconditions (desc), then success rate.

        Candidates with ALL preconditions met float to the top.
        Candidates missing some preconditions move toward the bottom.
        """
        scored: list = []
        for rec in candidates:
            name = rec.get('exploit') or rec.get('module', '')
            preconds = self.get_preconditions(name)
            if not preconds:
                fraction = 1.0
            else:
                met = sum((1 for p in preconds if known_features.get(p, False)))
                fraction = met / len(preconds)
            rate = self._success_rate(name)
            scored.append((rec, fraction, rate))
        scored.sort(key=lambda x: (-x[1], -x[2]))
        return [r for r, _, _ in scored]

    def find_chains(self, current_features: dict, goal: str='root_shell', max_depth: int=4) -> list:
        """
        BFS for exploit chain from current state to *goal*.
        Returns up to 5 chains (each a list of exploit names).
        """
        exploit_nodes = [nid for nid in self._node_ids() if self._get_node(nid).get('type') == 'Exploit']
        initial = frozenset((k for k, v in current_features.items() if v))
        if goal in initial:
            return [[]]
        queue = [(initial, [])]
        visited: set = {initial}
        results: list = []
        while queue and len(results) < 5:
            state, path = queue.pop(0)
            if len(path) >= max_depth:
                continue
            for ename in exploit_nodes:
                preconds = set(self.get_preconditions(ename))
                if not preconds.issubset(state):
                    continue
                effects = set(self.get_effects(ename))
                new_state = state | effects
                new_path = path + [ename]
                if goal in new_state:
                    results.append(new_path)
                    continue
                if new_state not in visited:
                    visited.add(new_state)
                    queue.append((new_state, new_path))
        return results

    def get_exploit_metadata(self, exploit_name: str) -> dict:
        return self._get_node(exploit_name)

    def all_exploits(self) -> list:
        return [nid for nid in self._node_ids() if self._get_node(nid).get('type') == 'Exploit']

    def _success_rate(self, name: str) -> float:
        node = self._get_node(name)
        if not node:
            return 0.5
        s = node.get('success_count', 0)
        f = node.get('failure_count', 0)
        return (s + 1) / (s + f + 2)

    def summary(self) -> dict:
        exploits = self.all_exploits()
        return {'total_nodes': len(self._node_ids()), 'total_exploits': len(exploits), 'total_edges': len(self._edge_list())}
