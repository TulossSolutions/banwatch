import sys
from typing import List


def print_banner():
    print(
        r"""
        * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
        *                                                                             *
        *    ██████╗  █████╗ ███╗   ██╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗    *
        *    ██╔══██╗██╔══██╗████╗  ██║██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║    *
        *    ██████╔╝███████║██╔██╗ ██║██║ █╗ ██║███████║   ██║   ██║     ███████║    *
        *    ██╔══██╗██╔══██║██║╚██╗██║██║███╗██║██╔══██║   ██║   ██║     ██╔══██║    *
        *    ██████╔╝██║  ██║██║ ╚████║╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║    *
        *    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝    *
        *                                                                             *
        *                       WATCH. DETECT. QUARANTINE.                            *
        * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
        """
    )
    print("         Defensive security scanner & brute-force quarantine")
    print("         As simple as UFW.\n")


def ask(prompt: str, options: List[str] = None, default: str = None) -> str:
    if options:
        default_idx = options.index(default) + 1 if default in options else None
        lines = [f"{i + 1}. {o}" for i, o in enumerate(options)]
        print("  " + "   ".join(lines))
        if default_idx:
            print(f"  Default: [{default_idx}] {default} (press Enter)")
            full = f"{prompt} (1-{len(options)} or Enter): "
        else:
            full = f"{prompt} (1-{len(options)}): "
    elif default:
        full = f"{prompt} [{default}]: "
    else:
        full = f"{prompt}: "

    while True:
        try:
            val = input(full).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(1)

        if not val and default:
            return default
        if options:
            if val.isdigit() and 1 <= int(val) <= len(options):
                return options[int(val) - 1]
            if val.lower() in [o.lower() for o in options]:
                return val
            print(f"  Please enter a number 1-{len(options)} or one of: {', '.join(options)}")
        else:
            return val


def ask_yesno(prompt: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    val = input(f"{prompt} {suffix}: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")
