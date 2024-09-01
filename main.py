import argparse
from gui import VulndowsPenGUI
from vulnerabilities import apply_vulnerabilities, VULNERABILITY_OPTIONS

def main():
    parser = argparse.ArgumentParser(description="VulndowsPen - Windows Vulnerability Configuration Tool")
    parser.add_argument("--cli", action="store_true", help="Run in command-line mode")
    parser.add_argument("--apply", nargs="+", help="Apply specific vulnerabilities")
    parser.add_argument("--difficulty", choices=["easy", "medium", "hard", "insane"], help="Set difficulty level")
    args = parser.parse_args()

    if args.cli:
        if args.difficulty:
            apply_difficulty(args.difficulty)
        elif args.apply:
            apply_vulnerabilities(args.apply)
        else:
            print("Please specify vulnerabilities to apply with --apply or set a difficulty level with --difficulty")
    else:
        app = VulndowsPenGUI()
        app.run()

def apply_difficulty(difficulty):
    if difficulty == "insane":
        apply_vulnerabilities([])  # Empty list triggers security measures
    else:
        percentages = {"easy": 1.0, "medium": 0.66, "hard": 0.33}
        num_vulnerabilities = int(len(VULNERABILITY_OPTIONS) * percentages[difficulty])
        vulnerabilities = VULNERABILITY_OPTIONS[:num_vulnerabilities]
        apply_vulnerabilities(vulnerabilities)

if __name__ == "__main__":
    main()