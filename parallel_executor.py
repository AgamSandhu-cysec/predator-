"""
Parallel Exploit Execution Engine

Attempts multiple exploits concurrently with resource management:
  - Thread pool for parallel execution
  - Success-first termination (stops as soon as one succeeds)
  - Resource limits to prevent system overload
  - Progress tracking for each exploit
  - Detailed failure diagnostics
"""
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import get_logger
logger = get_logger('ParallelExecutor')

class ParallelExploitExecutor:
    """
    Execute multiple exploits in parallel to speed up privilege escalation.
    
    Strategy:
      1. Sort exploits by confidence score
      2. Execute top N exploits in parallel (default: 3)
      3. Stop immediately when one succeeds
      4. Return the successful exploit result
    """

    def __init__(self, exploit_executor, max_parallel=3):
        self.exploit_executor = exploit_executor
        self.max_parallel = max_parallel
        self.success_flag = threading.Event()
        self.results_queue = queue.Queue()

    def execute_parallel(self, candidates, update_callback=None):
        """
        Execute multiple exploits in parallel.
        
        Args:
            candidates: List of exploit candidates (sorted by confidence)
            update_callback: Callback function for progress updates
        
        Returns:
            (success: bool, winning_exploit: dict or None)
        """

        def log(msg):
            if update_callback:
                update_callback(msg + '\n')
            logger.info(msg.strip())
        if not candidates:
            log('[red][-] No exploits to execute.[/red]')
            return (False, None)
        log(f'[bold cyan][*] Starting parallel execution of top {min(len(candidates), self.max_parallel)} exploits...[/bold cyan]')
        parallel_batch = candidates[:self.max_parallel]
        log('[cyan][*] Parallel batch:[/cyan]')
        for idx, cand in enumerate(parallel_batch, 1):
            log(f"[cyan]  [{idx}] {cand.get('name')} (confidence: {cand.get('confidence')})[/cyan]")
        with ThreadPoolExecutor(max_workers=self.max_parallel) as executor:
            futures = {}
            for cand in parallel_batch:
                future = executor.submit(self._execute_with_logging, cand, log)
                futures[future] = cand
            for future in as_completed(futures):
                cand = futures[future]
                try:
                    success = future.result()
                    if success:
                        log(f"[bold green][+] SUCCESS! Exploit '{cand.get('name')}' escalated privileges![/bold green]")
                        self.success_flag.set()
                        for f in futures:
                            if not f.done():
                                f.cancel()
                        return (True, cand)
                    else:
                        log(f"[yellow][!] Exploit '{cand.get('name')}' failed.[/yellow]")
                except Exception as e:
                    log(f"[red][-] Exploit '{cand.get('name')}' crashed: {e}[/red]")
        log('[bold red][-] All parallel exploits failed.[/bold red]')
        remaining = candidates[self.max_parallel:]
        if remaining:
            log(f'[cyan][*] Attempting {len(remaining)} remaining exploits sequentially...[/cyan]')
            for cand in remaining:
                if self.success_flag.is_set():
                    break
                log(f"[cyan][*] Trying: {cand.get('name')}...[/cyan]")
                try:
                    success = self.exploit_executor.execute(cand, update_callback)
                    if success:
                        log(f"[bold green][+] SUCCESS! Exploit '{cand.get('name')}' escalated privileges![/bold green]")
                        return (True, cand)
                except Exception as e:
                    log(f'[red][-] Exploit failed: {e}[/red]')
        return (False, None)

    def _execute_with_logging(self, candidate, log_callback):
        """Wrapper to execute exploit with thread-safe logging."""
        try:
            if self.success_flag.is_set():
                return False
            exploit_name = candidate.get('name', 'Unknown')

            def thread_log(msg):
                prefixed = f'[{exploit_name}] {msg}'
                log_callback(prefixed)
            success = self.exploit_executor.execute(candidate, thread_log)
            return success
        except Exception as e:
            logger.error(f"Parallel execution error for {candidate.get('name')}: {e}")
            return False

def execute_exploits_parallel(exploit_executor, candidates, update_callback=None, max_parallel=3):
    """Convenience wrapper for parallel exploit execution."""
    parallel_executor = ParallelExploitExecutor(exploit_executor, max_parallel)
    return parallel_executor.execute_parallel(candidates, update_callback)
