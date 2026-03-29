import json, sys
sys.path.insert(0, "src")
from llm_passthough_log.storage import analyze_token_breakdown

with open("proxy-data/logs.jsonl") as f:
    count = 0
    for line in f:
        try:
            entry = json.loads(line.strip())
        except:
            continue
        result = analyze_token_breakdown(entry)
        if result and count < 3:
            print(f"=== Entry {count+1} ===")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            print()
            count += 1
        if count >= 3:
            break

# Also count how many entries have analysis
total = 0
analyzed = 0
with open("proxy-data/logs.jsonl") as f:
    for line in f:
        try:
            entry = json.loads(line.strip())
        except:
            continue
        total += 1
        if analyze_token_breakdown(entry):
            analyzed += 1

print(f"\nTotal entries: {total}, With analysis: {analyzed}")
