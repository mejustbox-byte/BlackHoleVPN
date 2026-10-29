#!/usr/bin/env python3
"""Offline route recommendation from consecutive externally measured probes."""
import argparse
import json
import math
import sys


def recommend(data):
    if not isinstance(data, dict):
        raise ValueError('input must be an object')
    current = data.get('current')
    routes = data.get('routes')
    if not isinstance(current, str) or not current or not isinstance(routes, dict) or current not in routes:
        raise ValueError('current must identify a route in routes')
    if not routes:
        raise ValueError('routes must not be empty')
    scored = {}
    for name, samples in routes.items():
        if not isinstance(name, str) or not name or not isinstance(samples, list) or not samples:
            raise ValueError('each route needs a nonempty list of samples')
        for sample in samples:
            if not isinstance(sample, dict) or type(sample.get('ok')) is not bool:
                raise ValueError('each sample needs a boolean ok')
            latency = sample.get('latency_ms')
            if sample['ok'] and (type(latency) not in (int, float) or not math.isfinite(latency) or latency < 0):
                raise ValueError('successful samples require finite nonnegative latency_ms')
        recent = samples[-3:]
        # Two successes in three, including the latest, avoid one-sample flapping.
        healthy = len(recent) == 3 and recent[-1]['ok'] and sum(s['ok'] for s in recent) >= 2
        delays = sorted(s['latency_ms'] for s in recent if s['ok'])
        score = delays[len(delays)//2] if healthy else None
        scored[name] = score
    candidates = [(score, name) for name, score in scored.items() if score is not None]
    if not candidates:
        return {'decision': 'hold', 'route': current, 'reason': 'no healthy measured route', 'scores_ms': scored}
    best_score, best = min(candidates)
    current_score = scored[current]
    if current_score is None:
        return {'decision': 'recommend_switch', 'route': best, 'reason': 'current route unhealthy', 'scores_ms': scored}
    # Require both 25% and 50 ms improvement to prevent oscillation.
    if best != current and best_score <= current_score * 0.75 and current_score - best_score >= 50:
        return {'decision': 'recommend_switch', 'route': best, 'reason': 'alternative substantially faster', 'scores_ms': scored}
    return {'decision': 'hold', 'route': current, 'reason': 'current route healthy or improvement too small', 'scores_ms': scored}


def main():
    parser = argparse.ArgumentParser(description='Recommend a route from a JSON measurement file; does not probe or change configuration.')
    parser.add_argument('input', help='path to JSON measurements')
    args = parser.parse_args()
    try:
        with open(args.input, encoding='utf-8') as f:
            data = json.load(f, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite number')))
        print(json.dumps(recommend(data), ensure_ascii=False, indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 2
    return 0

if __name__ == '__main__':
    sys.exit(main())
