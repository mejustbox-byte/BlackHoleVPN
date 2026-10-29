"""Validate and summarize anonymized trial results; no network operations."""
import argparse
import json
import math
import re
import sys
from collections import defaultdict
from statistics import median

ID = re.compile(r'^[A-Za-z0-9_.-]{1,40}$')
STAGES = frozenset(range(1, 7))
STATUSES = frozenset(('pass', 'fail', 'not_run'))
FIELDS = frozenset(('stage', 'case', 'network', 'client', 'status', 'latency_ms'))


def summarize(data):
    if not isinstance(data, dict) or set(data) != {'results'} or not isinstance(data['results'],list) or len(data['results']) > 10000:
        raise ValueError('expected results array, max 10000 entries')
    totals = defaultdict(lambda: {'pass':0,'fail':0,'not_run':0,'latency':[]})
    for row in data['results']:
        if not isinstance(row,dict) or set(row) != FIELDS or type(row['stage']) is not int or row['stage'] not in STAGES:
            raise ValueError('invalid result fields')
        for key in ('case','network','client'):
            if not isinstance(row[key],str) or not ID.fullmatch(row[key]): raise ValueError('invalid anonymous label')
        if row['status'] not in STATUSES: raise ValueError('invalid status')
        latency=row['latency_ms']
        if latency is not None and (row['status'] != 'pass' or type(latency) not in (float,int) or not math.isfinite(latency) or latency < 0):
            raise ValueError('latency must be nonnegative and present only for pass')
        key=(row['stage'],row['case'],row['network'],row['client'])
        totals[key][row['status']] += 1
        if latency is not None: totals[key]['latency'].append(latency)
    groups=[]
    for (stage,case,network,client),v in sorted(totals.items()):
        run = v['pass']+v['fail']
        groups.append({'stage':stage,'case':case,'network':network,'client':client,'pass':v['pass'],'fail':v['fail'],'not_run':v['not_run'],'success_rate':v['pass']/run if run else None,'median_latency_ms':median(v['latency']) if v['latency'] else None})
    missing = sorted(STAGES - {g['stage'] for g in groups if g['pass']+g['fail']})
    return {'groups':groups, 'stages_without_measurements':missing}


def main(argv=None):
    parser=argparse.ArgumentParser(description='Summarize anonymized experiment records')
    parser.add_argument('input'); args=parser.parse_args(argv)
    try:
        with open(args.input,encoding='utf-8') as f: data=json.load(f,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite value')))
        print(json.dumps(summarize(data),indent=2,allow_nan=False))
        return 0
    except (ValueError,TypeError,OSError):
        print('error: invalid experiment data',file=sys.stderr); return 2

if __name__=='__main__': sys.exit(main())
