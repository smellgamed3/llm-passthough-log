import json, sys
sys.path.insert(0, "src")
from llm_passthough_log.storage import analyze_token_breakdown

# Find entry with tools
with open("proxy-data/logs.jsonl") as f:
    for line in f:
        try:
            entry = json.loads(line.strip())
        except:
            continue
        rb = entry.get("request_body")
        if isinstance(rb, dict) and rb.get("tools"):
            result = analyze_token_breakdown(entry)
            if result:
                print("=== Entry with tools ===")
                print(json.dumps(result, indent=2, ensure_ascii=False))
                break

# Find entry with multiple roles 
with open("proxy-data/logs.jsonl") as f:
    for line in f:
        try:
            entry = json.loads(line.strip())
        except:
            continue
        rb = entry.get("request_body")
        if isinstance(rb, dict) and isinstance(rb.get("messages"), list):
            roles = set(m.get("role") for m in rb["messages"] if isinstance(m, dict))
            if len(roles) >= 3:
                result = analyze_token_breakdown(entry)
                if result:
                    print("\n=== Entry with 3+ roles ===")
                    print(json.dumps(result, indent=2, ensure_ascii=False))
                    break

# Find entry with real usage + tools
with open("proxy-data/logs.jsonl") as f:
    for line in f:
        try:
            entry = json.loads(line.strip())
        except:
            continue
        rb = entry.get("request_body")
        resp = entry.get("response_body")
        has_usage = (isinstance(resp, dict) and resp.get("usage")) or (isinstance(resp, str) and "usage" in resp)
        if isinstance(rb, dict) and rb.get("tools") and has_usage:
            result = analyze_token_breakdown(entry)
            if result:
                print("\n=== Entry with tools + real usage (scaled) ===")
                print(json.dumps(result, indent=2, ensure_ascii=False))
                break
