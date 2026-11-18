"""Manual live connectivity test for Google Gemini API.

Usage:
    python tests/test_live_connectivity.py
    # or with pytest:
    pytest tests/test_live_connectivity.py -m live

Requirements:
    GEMINI_API_KEY must be set in your .env file or environment.
"""

import asyncio
import os
import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
from app.config import get_settings
from app.providers.gemini import GeminiProvider


async def run_live_connectivity_check() -> int:
    """Execute live end-to-end check against Gemini API."""
    # Load .env if present
    load_dotenv(PROJECT_ROOT / ".env")
    settings = get_settings()

    print("\n" + "=" * 60)
    print(" LLM Sentinel - Gemini Provider Live Connectivity Check")
    print("=" * 60)
    print(f"Provider:  {settings.llm_provider}")
    print(f"Model:     {settings.gemini_model}")
    print(f"API Key:   {'Configured (Hidden)' if settings.is_gemini_configured else 'NOT CONFIGURED'}")
    print("-" * 60)

    if not settings.is_gemini_configured:
        print("[!] ERROR: GEMINI_API_KEY is not set.")
        print("    Please set GEMINI_API_KEY in llm-sentinel/.env or export it in your environment.")
        print("    Example: GEMINI_API_KEY=AIzaSy...")
        print("=" * 60 + "\n")
        return 1

    provider = GeminiProvider(
        api_key=settings.gemini_api_key,
        model=settings.gemini_model,
    )

    print("[*] Probing Gemini API connectivity...")
    start_time = time.perf_counter()

    status = await provider.test_connectivity()
    elapsed = time.perf_counter() - start_time

    if status.status == "connected":
        print(f"[+] SUCCESS: Upstream Gemini responded in {elapsed:.2f}s.")
        print(f"    Details: {status.details}")

        # Send a brief test prompt
        print("[*] Testing generation with minimal test prompt...")
        try:
            gen_start = time.perf_counter()
            response = await provider.generate(
                prompt="Briefly confirm you are online and ready for security testing in under 15 words.",
                max_tokens=30,
            )
            gen_elapsed = time.perf_counter() - gen_start
            print(f"[+] Model Response ({gen_elapsed:.2f}s): \"{response.response.strip()}\"")
            if response.usage:
                print(f"    Tokens - Prompt: {response.usage.prompt_tokens}, Completion: {response.usage.completion_tokens}, Total: {response.usage.total_tokens}")
            print("\n[+] Provider is 100% operational and ready for Phase 2 security testing POC.")
            print("=" * 60 + "\n")
            return 0
        except Exception as exc:
            print(f"[-] Generation probe failed: {exc}")
            return 1
    else:
        print(f"[-] FAILED: Upstream connectivity failed in {elapsed:.2f}s.")
        print(f"    Status: {status.status}")
        print(f"    Details: {status.details}")
        print("=" * 60 + "\n")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(run_live_connectivity_check())
    sys.exit(exit_code)

