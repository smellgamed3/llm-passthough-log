import json

usages = set()
example_full = None
with open('proxy-data/logs.jsonl') as f:
    for line in f:
        try:
            entry = json.loads(line.strip())
        except:
            continue
        rb = entry.get('response_body')
        if isinstance(rb, dict) and rb.get('usage'):
            u = rb['usage']
            for k, v in u.items():
                usages.add(k)
                if isinstance(v, dict):
                    for k2 in v:
                        usages.add(f'{k}.{k2}')
            if len(u) > 3 and not example_full:
                example_full = u
        if isinstance(rb, str) and 'usage' in rb:
            for ln in rb.split('\n'):
                if ln.startswith('data: ') and 'usage' in ln:
                    payload = ln[6:].strip()
                    if payload == '[DONE]':
                        continue
                    try:
                        c = json.loads(payload)
                        if c.get('usage'):
                            for k, v in c['usage'].items():
                                usages.add(k)
                                if isinstance(v, dict):
                                    for k2 in v:
                                        usages.add(f'{k}.{k2}')
                            if len(c['usage']) > 3 and not example_full:
                                example_full = c['usage']
                    except:
                        pass

print("=== All usage fields ===")
for u in sorted(usages):
    print(u)
print("\n=== Example full usage ===")
if example_full:
    print(json.dumps(example_full, indent=2))
