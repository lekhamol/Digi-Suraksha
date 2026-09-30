import sys
import argparse
from threat_engine import ThreatEngine
import json

def main():
    parser = argparse.ArgumentParser(description="Digi Suraksha - AI Threat Detection CLI Scanner")
    parser.add_argument("--url", type=str, help="Analyze target URL for phishing / typosquatting")
    parser.add_argument("--message", type=str, help="Analyze SMS / chat text message for scam indicators")
    parser.add_argument("--password", type=str, help="Check password security and exposure")
    parser.add_argument("--json", action="store_true", help="Output result as raw JSON")

    args = parser.parse_args()
    engine = ThreatEngine()

    if args.url:
        res = engine.analyze_url(args.url)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print("\n" + "="*50)
            print("  DIGI SURAKSHA - URL THREAT ANALYSIS")
            print("="*50)
            print(f" Target URL     : {res['url']}")
            print(f" Risk Level     : {res['risk_level']}")
            print(f" Risk Score     : {res['risk_score']}%")
            print(f" Domain Entropy : {res.get('entropy', 'N/A')}")
            print("-" * 50)
            print(" Threat Indicators:")
            for ind in res['indicators']:
                print(f"  [!] {ind}")
            print("-" * 50)
            print(" Detailed Reasons:")
            for r in res['reasons']:
                print(f"  - {r}")
            print("-" * 50)
            print(f" Recommendation : {res['recommendation']}")
            print("="*50 + "\n")

    elif args.message:
        res = engine.analyze_message(args.message)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print("\n" + "="*50)
            print("  DIGI SURAKSHA - MESSAGE THREAT ANALYSIS")
            print("="*50)
            print(f" Message Text   : {res['message'][:60]}...")
            print(f" Risk Level     : {res['risk_level']}")
            print(f" Risk Score     : {res['risk_score']}%")
            print(f" AI Confidence  : {res['ai_confidence']}%")
            print("-" * 50)
            print(" Detected Indicators:")
            for ind in res['indicators']:
                print(f"  [!] {ind}")
            print("-" * 50)
            print(" Analysis Breakdown:")
            for r in res['reasons']:
                print(f"  - {r}")
            print("-" * 50)
            print(f" Recommendation : {res['recommendation']}")
            print("="*50 + "\n")

    elif args.password:
        res = engine.analyze_password(args.password)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print("\n" + "="*50)
            print("  DIGI SURAKSHA - PASSWORD STRENGTH CHECK")
            print("="*50)
            print(f" Status         : {res['status']}")
            print(f" Score          : {res['strength_score']}/100")
            print(f" Entropy        : {res['entropy_bits']} bits")
            print(f" Recommendation : {res['recommendation']}")
            print("="*50 + "\n")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
