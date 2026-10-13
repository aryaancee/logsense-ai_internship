"""Check that your AI provider works.  Run from this folder:  python check_ai.py"""
from logsense import llm

s = llm.status()
print("Provider:", s["provider"], "| model:", s["model"])
if not s["provider"]:
    raise SystemExit("No key found. Put GEMINI_API_KEY=your_key in the .env file (this folder), save it, and run again.")
out = llm.complete("Reply with the single word OK.", 20)
print("WORKS - AI replied:", out.strip()) if out else print("FAILED:", llm.last_error)
