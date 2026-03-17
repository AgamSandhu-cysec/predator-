"""
brain/brain.py

PredatorBrain — central orchestrator that wires all brain sub-systems.

Typical call sequence (from predator.py auto-exploit worker):

    brain = PredatorBrain(config)
    brain.startup(session)                      # retrain + crowd download
    features = brain.extract_features(raw_results, session)
    recs     = brain.recommend(features, raw_results)
    # ... run exploits ...
    brain.record_outcome("sudo_abuse", features, success=True, duration=4.2)
    brain.shutdown()
"""
import os
import time
from utils.logger import get_logger
logger = get_logger('PredatorBrain')
from brain.feature_schema import FEATURE_NAMES
from brain.feedback_logger import FeedbackLogger
from brain.adaptive_ml import AdaptiveMLEngine
from brain.rl_selector import ThompsonSamplingSelector
from brain.knowledge_graph import ExploitKnowledgeGraph
from brain.planner import plan_attack, load_exploit_actions, plan_to_recommendations
from brain.self_debugger import SelfDebugger
from brain.hardening_detector import HardeningDetector
from brain.manual_recorder import ManualRecorder
from brain.crowd_client import CrowdClient
from brain.llm_advisor import LLMAdvisor

class PredatorBrain:
    """
    The Predator Brain: adaptive ML + knowledge graph + A* planner +
    Thompson sampling + self-debugging + hardening detection +
    manual feedback loop + crowd intelligence.

    All sub-systems are optional/configurable via config.yaml[brain].
    """

    def __init__(self, config: dict):
        brain_cfg = config.get('brain', {})
        self.feedback_logger = FeedbackLogger(brain_cfg.get('feedback_db', 'brain/data/feedback.db'))
        self.ml_engine = AdaptiveMLEngine(brain_cfg)
        self.knowledge_graph = ExploitKnowledgeGraph(brain_cfg.get('graph_path', 'brain/data/exploit_graph.json'))
        self.rl_selector = ThompsonSamplingSelector(self.feedback_logger)
        self.llm = LLMAdvisor(brain_cfg.get('llm', {}))
        self.debugger = SelfDebugger(llm_advisor=self.llm)
        self.hardening_detector = HardeningDetector()
        self._hardening_cache: dict = {}
        self.recorder = ManualRecorder(output_dir='exploits/user_defined', llm_advisor=self.llm)
        self.crowd = CrowdClient(brain_cfg.get('crowd', {}))
        self._actions: list = []
        self._last_feature_vec: list = []
        self._target_id: str = ''
        self._has_python: bool = True
        self._has_gcc: bool = True
        logger.info('PredatorBrain initialised.')

    def startup(self, session=None):
        """
        Run on connect:
          - Retrain model from history
          - Download crowd stats
          - Load planner actions
          - Detect target capabilities
        """
        logger.info('Brain startup sequence...')
        self.ml_engine.retrain_from_history(self.feedback_logger)
        global_stats = self.crowd.download_stats()
        if global_stats:
            local = self.feedback_logger.get_thompson_counts()
            merged = self.crowd.merge_global_rates(local, global_stats)
            logger.info(f'Merged crowd stats for {len(merged)} exploits.')
        self._actions = load_exploit_actions()
        if session:
            self._detect_capabilities(session)
        logger.info('Brain startup complete.')

    def shutdown(self):
        """Persist model on clean exit."""
        self.ml_engine._save()
        logger.info('Brain state saved.')

    def extract_features(self, raw_results: dict, session=None) -> dict:
        """
        Build a full feature dict from enumeration results.
        Also sets the numeric feature vector for ML consumption.
        """
        from enumerator.feature_extractor import FeatureExtractor
        extractor = FeatureExtractor(raw_results)
        features = extractor.get_feature_vector()
        features['user_shell'] = True
        features['has_python3'] = self._has_python
        features['has_gcc'] = self._has_gcc
        if session:
            features = self._fill_feature_gaps(features, session)
        self._last_feature_vec = [float(features.get(f, 0)) for f in FEATURE_NAMES]
        return features

    def _fill_feature_gaps(self, features: dict, session) -> dict:
        """Run targeted probes for features still unknown (None)."""
        GAP_CMDS = {'writable_passwd': 'test -w /etc/passwd && echo YES || echo NO', 'writable_shadow': 'test -r /etc/shadow && echo YES || echo NO', 'in_lxd_group': 'id | grep -q lxd && echo YES || echo NO', 'in_docker_group': 'id | grep -q docker && echo YES || echo NO', 'cap_setuid': 'grep -c cap_setuid /proc/self/status 2>/dev/null || echo 0', 'nfs_no_root_squash': 'grep -q no_root_squash /etc/exports 2>/dev/null && echo YES || echo NO', 'ld_preload_possible': 'test -w /etc/ld.so.conf.d && echo YES || echo NO', 'cron_writable_script': 'find /etc/cron* /var/spool/cron -writable 2>/dev/null | head -1'}
        for feat, cmd in GAP_CMDS.items():
            if features.get(feat) is None:
                try:
                    out, _, c = session.run_command(cmd, timeout=4)
                    if feat in ('cap_setuid',):
                        features[feat] = int(out.strip() or 0) > 0
                    elif feat == 'cron_writable_script':
                        features[feat] = bool(out.strip())
                    else:
                        features[feat] = 'YES' in out.upper()
                except Exception:
                    features[feat] = False
        return features

    def recommend(self, features: dict, raw_results: dict | None=None, session=None) -> list:
        """
        Full recommendation pipeline:
          1. ML prediction (or rule-based fallback)
          2. Knowledge graph pre-condition filtering
          3. Thompson sampling reorder
          4. Hardening penalty
          5. Planner chain prepended

        Returns ordered list of exploit recommendation dicts.
        """
        ml_recs = self.ml_engine.predict(self._last_feature_vec)
        if not ml_recs:
            ml_recs = self._rule_based_rank(features)
        filtered = self.knowledge_graph.filter_by_preconditions(ml_recs, features)
        ordered = self.rl_selector.select(filtered)
        if self._hardening_cache:
            ordered = self.hardening_detector.penalise_scores(ordered, self._hardening_cache)
        plans = plan_attack(features, self._actions, goal='root_shell', max_plans=1)
        if plans:
            plan_recs = plan_to_recommendations(plans[0])
            ordered_mods = {r.get('module') or r.get('exploit') for r in ordered}
            novel_plan_recs = [r for r in plan_recs if r['module'] not in ordered_mods]
            ordered = novel_plan_recs + ordered
        if raw_results and self.llm.enabled:
            peas_output = raw_results.get('peas_output', '')
            if peas_output:
                llm_recs = self.llm.analyse(peas_output)
                ordered = ordered + llm_recs
        logger.info(f'Brain recommendation: {len(ordered)} exploit candidates.')
        return ordered

    def record_outcome(self, exploit_name: str, features: dict, success: bool, duration: float=0.0, error: str=''):
        """
        Call after every exploit attempt to feed all learning systems.
        """
        fv = self._last_feature_vec
        self.feedback_logger.log(exploit_name, fv, success, duration, error, self._target_id)
        self.ml_engine.update(fv, exploit_name, success)
        self.knowledge_graph.record_outcome(exploit_name, success)
        try:
            self.crowd.upload(self.feedback_logger)
        except Exception:
            pass

    def diagnose_failure(self, exploit_name: str, error_output: str) -> dict:
        """Delegate to self_debugger."""
        return self.debugger.diagnose(exploit_name, error_output)

    def auto_fix(self, category: str, exploit_rec: dict, session=None) -> dict | None:
        """Delegate to self_debugger."""
        return self.debugger.auto_fix(category, exploit_rec, session)

    def probe_hardening(self, session) -> dict:
        """Run hardening checks and cache results."""
        self._hardening_cache = self.hardening_detector.probe(session)
        return self._hardening_cache

    def hardening_report(self) -> str:
        return self.hardening_detector.format_report(self._hardening_cache)

    def start_recording(self):
        self.recorder.start()

    def record_command(self, cmd: str, output: str=''):
        self.recorder.record(cmd, output)

    def stop_recording(self):
        self.recorder.stop()

    def prompt_save_session(self) -> str | None:
        return self.recorder.prompt_and_save(self.knowledge_graph)

    def _rule_based_rank(self, features: dict) -> list:
        """
        Fallback (ML not ready): score exploits by number of met preconditions.
        """
        all_exploits = self.knowledge_graph.all_exploits()
        scored = []
        for name in all_exploits:
            preconds = self.knowledge_graph.get_preconditions(name)
            if not preconds:
                frac = 1.0
            else:
                met = sum((1 for p in preconds if features.get(p, False)))
                frac = met / len(preconds)
            rate = self.knowledge_graph._success_rate(name)
            scored.append({'name': name.replace('_', ' ').title(), 'exploit': name, 'module': name, 'type': 'manual', 'confidence': round(frac * rate, 3), 'source': 'rules', 'reason': f'{int(frac * 100)}% preconditions met'})
        scored.sort(key=lambda x: -x['confidence'])
        return scored

    def _detect_capabilities(self, session):
        """Detect python/gcc availability on the target."""
        try:
            py_out, _, py_code = session.run_command('which python3 python 2>/dev/null | head -1')
            self._has_python = py_code == 0 and bool(py_out.strip())
            _, _, gcc_code = session.run_command('command -v gcc 2>/dev/null')
            self._has_gcc = gcc_code == 0
            logger.info(f'Target capabilities: python={self._has_python}, gcc={self._has_gcc}')
        except Exception:
            pass

    def set_target(self, host: str, user: str=''):
        self._target_id = f'{host}:{user}'

    def stats(self) -> dict:
        kg_summary = self.knowledge_graph.summary()
        return {'ml_updates': self.ml_engine.get_update_count(), 'ml_ready': self.ml_engine.is_ready(), 'db_records': self.feedback_logger.total_attempts(), 'graph_exploits': kg_summary['total_exploits'], 'graph_nodes': kg_summary['total_nodes'], 'hardening_active': self.hardening_detector.any_active(self._hardening_cache), 'thompson_rates': self.rl_selector.get_success_rates()}
