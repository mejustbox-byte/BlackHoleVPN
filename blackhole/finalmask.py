"""Construct opt-in Xray outbound fragmentation settings for experiments."""
import copy
import re


def _range(value, *, minimum, maximum):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?', value):
        raise ValueError('expected integer or ascending integer range')
    numbers=[int(x) for x in value.split('-')]
    if len(numbers)==1: numbers.append(numbers[0])
    if not minimum <= numbers[0] <= numbers[1] <= maximum:
        raise ValueError('range outside supported experimental bounds')
    return value


def add_tlshello_fragment(outbound, lengths=('10-20',), delays=('10-20',), max_split='3-6'):
    """Return a copy; never alter input or overwrite existing FinalMask settings."""
    if not isinstance(outbound,dict): raise ValueError('expected outbound object')
    stream=outbound.get('streamSettings')
    if not isinstance(stream,dict) or stream.get('security') != 'reality' or stream.get('network') not in ('tcp','raw','xhttp'):
        raise ValueError('requires a compatible REALITY outbound')
    if 'finalmask' in stream: raise ValueError('refusing to overwrite existing finalmask')
    if not isinstance(lengths,(tuple,list)) or not isinstance(delays,(tuple,list)) or not 1 <= len(lengths) <= 8 or not 1 <= len(delays) <= 8:
        raise ValueError('one to eight fragment parameters required')
    clean_lengths=[_range(x,minimum=1,maximum=4096) for x in lengths]
    clean_delays=[_range(x,minimum=0,maximum=1000) for x in delays]
    clean_split=_range(max_split,minimum=1,maximum=64)
    output=copy.deepcopy(outbound)
    output['streamSettings']['finalmask']={'tcp':[{'type':'fragment','settings':{'packets':'tlshello','lengths':clean_lengths,'delays':clean_delays,'maxSplit':clean_split}}]}
    return output
