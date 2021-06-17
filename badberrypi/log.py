import logging
import sys

logging.basicConfig(format="[%(asctime)s]%(message)s", level=logging.INFO)
loger = logging.getLogger("badberrypi")


def attack(_):
    loger.info(f"\x1b[1;31;40m[-]{str(_)}\x1b[0m")


def detect(_):
    loger.info(f"\x1b[6;30;42m[!]{str(_)}\x1b[0m")


def success(_):
    loger.info(f"\033[92m[+]{str(_)}\x1b[0m")
    return True


def info(_):
    loger.info(f"\033[94m[=]{str(_)}\033[0m")
    return True


def error(_):
    loger.error(f"\033[91m[x]{str(_)}\033[0m")
    return False


def end(_=""):
    if _:
        error(_)
    sys.exit()


def debug(*_, debug=False):
    if debug:
        loger.debug(f"\033[95m[^]{str(_)}\033[0m")
