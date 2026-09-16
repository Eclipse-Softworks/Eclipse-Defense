import logging


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"

    @classmethod
    def disable(cls):
        """Replace ANSI escape codes with empty strings for plain-text output."""
        for name, value in vars(cls).items():
            if name.isupper() and isinstance(value, str):
                setattr(cls, name, "")


logger = logging.getLogger("eclipse")


def banner():
    border = "=" * 60
    heading = (
        "  ____  _____ ____ _   _ ____  ___ _______   __\n"
        " / ___|| ____/ ___| | | |  _ \\|_ _|_   _\\ \\ / /\n"
        " \\___ \\|  _|| |   | | | | |_) || |  | |  \\ V / \n"
        "  ___) | |__| |___| |_| |  _ < | |  | |   | |  \n"
        " |____/|_____\\____|\\___/|_| \\_\\___| |_|   |_|  \n"
    )
    banner_text = (
        f"\n{Color.CYAN}{Color.BOLD}\n" + heading
        + f"\n{Color.RESET}{Color.GRAY}  Eclipse Softworks CyberDefense{Color.RESET}\n"
        + f"{Color.GRAY}  {border}{Color.RESET}\n"
    )
    logger.info(banner_text)


def label_vuln(level):
    levels = {
        "CRITICAL": f"{Color.BG_RED}{Color.WHITE}{Color.BOLD} CRITICAL {Color.RESET}",
        "HIGH": f"{Color.RED}{Color.BOLD} [HIGH]    {Color.RESET}",
        "MEDIUM": f"{Color.YELLOW}{Color.BOLD} [MEDIUM]  {Color.RESET}",
        "LOW": f"{Color.CYAN}{Color.BOLD} [LOW]     {Color.RESET}",
        "INFO": f"{Color.BLUE}{Color.BOLD} [INFO]    {Color.RESET}",
        "PASS": f"{Color.GREEN}{Color.BOLD} [PASS]    {Color.RESET}",
        "FAIL": f"{Color.RED}{Color.BOLD} [FAIL]    {Color.RESET}",
    }
    return levels.get(level.upper(), f"[{level}]")


def section(title):
    border = "=" * 60
    logger.info(f"\n{Color.MAGENTA}{Color.BOLD}{border}{Color.RESET}")
    logger.info(f"{Color.MAGENTA}{Color.BOLD}  {title}{Color.RESET}")
    logger.info(f"{Color.MAGENTA}{Color.BOLD}{border}{Color.RESET}")


def result(level, message):
    prefix = f" {label_vuln(level)} {Color.WHITE}"
    suffix = Color.RESET
    logger.info(prefix + str(message) + suffix)


def info(message):
    logger.info(f" {Color.GRAY}>{Color.RESET} {message}")


def found(message):
    prefix = f" {Color.RED}[!]{Color.RESET} {Color.RED}{Color.BOLD}"
    suffix = Color.RESET
    logger.info(prefix + str(message) + suffix)


def ok(message):
    prefix = f" {Color.GREEN}[+]{Color.RESET} {Color.GREEN}"
    suffix = Color.RESET
    logger.info(prefix + str(message) + suffix)
