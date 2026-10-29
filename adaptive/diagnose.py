"""One-shot diagnostics; operator supplies two or more local route proxies."""
import argparse
import json
import sys
import time
from adaptive.behavior import Analyzer
from adaptive.probe import measure_round, validate_target, validate_proxy


def main(argv=None):
    parser=argparse.ArgumentParser(description='Measure configured routes; never switches connections')
    parser.add_argument('--config',required=True,help='JSON file with target, current and routes')
    parser.add_argument('--rounds',type=int,default=3,choices=range(3,11))
    parser.add_argument('--interval',type=float,default=10)
    args=parser.parse_args(argv)
    try:
        if not 10 <= args.interval <= 300: raise ValueError('interval must be 10–300 seconds')
        with open(args.config,encoding='utf-8') as f:
            config=json.load(f,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite number')))
        routes=config['routes']; current=config['current']; target=config['target']
        if not isinstance(routes,dict) or not 2 <= len(routes) <= 16: raise ValueError('two to sixteen routes required')
        proxies={name:(item['host'],item['port']) for name,item in routes.items() if isinstance(item,dict)}
        if len(proxies) != len(routes): raise ValueError('invalid route')
        validate_target(target)
        for host,port in proxies.values(): validate_proxy(host,port)
        analyzer=Analyzer(list(proxies),window_seconds=max(300,(args.rounds-1)*args.interval+120))
        if current not in proxies: raise ValueError('invalid current route')
        for i in range(args.rounds):
            if i: time.sleep(args.interval)
            measure_round(analyzer,target,proxies)
        # No local network check is performed; do not claim a diagnosis of DPI.
        print(json.dumps(analyzer.analyze(current),indent=2,allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('error: invalid configuration or probe setup',file=sys.stderr)
        return 2

if __name__=='__main__': sys.exit(main())
