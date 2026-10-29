"""Bounded, local analysis of opt-in probe metadata; no packet inspection."""
import math
import re
import time
from collections import deque
from statistics import median

ROUTE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')

class Analyzer:
    def __init__(self, routes, max_samples=20, window_seconds=300, cooldown_seconds=120, clock=time.monotonic):
        if not isinstance(routes, (list, tuple)) or not 1 <= len(routes) <= 16 or any(not isinstance(r,str) or not ROUTE.fullmatch(r) for r in routes) or len(set(routes)) != len(routes):
            raise ValueError('routes must contain 1–16 distinct safe identifiers')
        if type(max_samples) is not int or not 3 <= max_samples <= 100:
            raise ValueError('max_samples must be an integer from 3 to 100')
        if type(window_seconds) not in (int,float) or not math.isfinite(window_seconds) or window_seconds <= 0 or type(cooldown_seconds) not in (int,float) or not math.isfinite(cooldown_seconds) or cooldown_seconds < 0:
            raise ValueError('invalid time settings')
        self._samples = {r: deque(maxlen=max_samples) for r in routes}
        self.window = window_seconds
        self.cooldown = cooldown_seconds
        self.clock = clock
        self.last_switch = None

    def observe(self, route, ok, latency_ms=None):
        if route not in self._samples or type(ok) is not bool:
            raise ValueError('unknown route or invalid result')
        if ok and (type(latency_ms) not in (int,float) or not math.isfinite(latency_ms) or latency_ms < 0):
            raise ValueError('successful probe needs a finite nonnegative latency')
        if not ok and latency_ms is not None:
            raise ValueError('failed probe must not include latency')
        self._samples[route].append((self.clock(), ok, latency_ms))

    def analyze(self, current, network_available=True):
        if current not in self._samples or type(network_available) is not bool:
            raise ValueError('invalid current route or network state')
        now = self.clock()
        stats = {}
        for route, history in self._samples.items():
            recent = [s for s in history if 0 <= now-s[0] <= self.window]
            success = [s[2] for s in recent if s[1]]
            tail = recent[-3:]
            healthy = len(tail) == 3 and tail[-1][1] and sum(s[1] for s in tail) >= 2
            stats[route] = {'samples':len(recent), 'failures':len(recent)-len(success), 'median_ms':median(success) if success else None, 'healthy':healthy}
        decision = {'decision':'hold', 'route':current, 'reason':'no healthy measured route', 'routes':stats}
        if not network_available:
            decision['reason'] = 'local network unavailable'
            return decision
        candidates = [(s['median_ms'], name) for name,s in stats.items() if s['healthy']]
        if not candidates: return decision
        best_score, best = min(candidates)
        current_stats = stats[current]
        if best == current:
            decision['reason'] = 'current route healthy'
            return decision
        improvement = current_stats['healthy'] and best_score <= current_stats['median_ms'] * 0.75 and current_stats['median_ms']-best_score >= 50
        if not current_stats['healthy'] or improvement:
            if self.last_switch is not None and now-self.last_switch < self.cooldown:
                decision['reason'] = 'switch cooldown'
            else:
                decision.update(decision='recommend_switch', route=best, reason='current route unhealthy' if not current_stats['healthy'] else 'alternative substantially faster')
        else:
            decision['reason'] = 'improvement too small'
        return decision

    def confirm_switch(self):
        """Caller invokes only after a real switch succeeds; no switching occurs here."""
        self.last_switch = self.clock()
