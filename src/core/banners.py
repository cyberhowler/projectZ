"""
ProjectZ - Banner Collection
Random banner on every launch — Metasploit style.
10 unique wolf/hacker ASCII art banners with color themes.
"""

import random
from colorama import Fore, Style

# ── Colour shortcuts ──────────────────────────────────────────────────────────
def _b(c, bright=True):
    return c + (Style.BRIGHT if bright else Style.DIM)

RS = Style.RESET_ALL
DM = Style.DIM
W  = Fore.WHITE  + Style.BRIGHT
C  = Fore.CYAN   + Style.BRIGHT
B  = Fore.BLUE   + Style.BRIGHT
M  = Fore.MAGENTA+ Style.BRIGHT
R  = Fore.RED    + Style.BRIGHT
G  = Fore.GREEN  + Style.BRIGHT
Y  = Fore.YELLOW + Style.BRIGHT
CY = Fore.CYAN
WH = Fore.WHITE
GR = Fore.GREEN
RE = Fore.RED
BL = Fore.BLUE
MA = Fore.MAGENTA

# ─────────────────────────────────────────────────────────────────────────────
#  PROJECTZ LOGO  (always the same, below every wolf)
# ─────────────────────────────────────────────────────────────────────────────
def _logo(color1=C, color2=W, color3=B):
    return f"""
{color1}  ██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗███████╗{RS}
{color1}  ██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝╚════██║{RS}
{color2}  ██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║       ██╔╝ {RS}
{color2}  ██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║      ██╔╝  {RS}
{color3}  ██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║      ██║   {RS}
{color3}  ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝      ╚═╝  {RS}"""

def _tagline(sep_color=C, credit_color=W, quote=""):
    q = f"\n  {DM}  \"{quote}\"{RS}" if quote else ""
    return f"""
{sep_color}  ╼━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╾{RS}
  {DM}    Open Source Intelligence Framework  ·  56 Modules  ·  v1.0{RS}{q}
  {DM}                       developed by{RS} {credit_color}cyberhowler{RS} {Y}(R.G){RS}
{sep_color}  ╼━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╾{RS}
"""


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 1 — Howling Wolf in Circle  (your original sketch)
# ═════════════════════════════════════════════════════════════════════════════
def banner_1():
    art = f"""
{DM}                      · · · · · · ·                          {RS}
{DM}                  ·  ´             ` ·                       {RS}
{BL}               ·    (   /\\     /\\   )    ·                  {RS}
{BL}             ·      | /^^\\   /^^\\  |      ·                 {RS}
{B}           ·        |/  /\\ X /\\  \\|        ·               {RS}
{B}          ·         |  < ◈ | ◈ >  |         ·               {RS}
{B}         ·          | \\_\\_\\|/_/_/ |          ·              {RS}
{W}        ·           |   \\___|___/  |           ·             {RS}
{W}       ·            |  ___/|\\___   |            ·            {RS}
{W}      ·             | /  /|||\\  \\  |             ·           {RS}
{W}     ·              |/ /  |^|  \\ \\|              ·          {RS}
{C}     ·               \\ \\__|_|__/ /               ·          {RS}
{C}      ·               \\  /|||\\  /               ·           {RS}
{C}        ·              \\_/ | \\_/              ·             {RS}
{CY}          ·             /  |^|  \\           ·               {RS}
{DM}             ·  ·  ·  ·    | |    ·  ·  ·  ·                {RS}"""
    return art + _logo(C, W, B) + _tagline(C, W, "The lone wolf survives — the pack thrives.")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 2 — Large Tattoo Howling Wolf (side profile)
# ═════════════════════════════════════════════════════════════════════════════
def banner_2():
    art = f"""
{DM}                                              __....-----{RS}
{B}                                    ___....---´    _____/{RS}
{B}                           ___...--´          ____/  //{RS}
{W}                  ____....´      __________//___/ ////{RS}
{W}             ____/           ___/  /\\  /\\  / /  ////{RS}
{W}            /    \\__________/ /\\  /  \\/  \\/  / ////{RS}
{C}           / ◈    \\  _  _  \\ \\/\\/  /\\  /\\ / ////{RS}
{C}          |       |_/ \\/ \\_|/\\/\\/\\/  \\/  \\/  ///{RS}
{C}          |  /\\__/ |  /\\  /\\ \\ /\\ \\  /\\  /  ///{RS}
{B}          \\ / /   \\| /  \\/  \\ X  \\ \\/  \\/ ////{RS}
{B}           X /  ◈  |/   /\\   |/\\   \\   / ////{RS}
{W}           |\\ \\____|\\ __\\/\\__|  \\___\\_/ ///{RS}
{W}           | \\      \\/ /  \\  \\|   /  / ///{RS}
{W}           |  \\______\\/    \\__\\__/  / ///{RS}
{CY}           \\          \\    /    \\  / ///{RS}
{CY}            \\__________\\  /______\\/ //{RS}
{DM}                         \\/          /{RS}
{DM}                          \\__________/{RS}"""
    return art + _logo(B, W, C) + _tagline(B, W, "Hunt in silence. Strike in data.")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 3 — Minimalist Tribal Wolf
# ═════════════════════════════════════════════════════════════════════════════
def banner_3():
    art = f"""
{DM}
{R}       /\\      /\\                                           {RS}
{R}      /  \\    /  \\                                          {RS}
{R}     / /\\ \\  / /\\ \\                                        {RS}
{RE}    / /  \\_\\/ /  \\ \\                                       {RS}
{RE}   / /   ◈   ◈   \\ \\                                      {RS}
{W}  / /    \\_____/    \\ \\                                    {RS}
{W} / /   __/     \\__   \\ \\                                   {RS}
{W}/ /  _/ /\\___/\\ \\_\\   \\ \\                                 {RS}
{W}\\ \\ / \\/  _^_  \\/ / \\  / /                                {RS}
{C} \\ X  | /|   |\\ |  X  X /                                  {RS}
{C}  \\ \\ |/ |___|  \\| /\\ / /                                  {RS}
{C}   \\ \\|  |   |   |/  X /                                   {RS}
{CY}    \\ \\  \\ | /  /   / /                                    {RS}
{CY}     \\ \\__\\|/___/  / /                                     {RS}
{DM}      \\____________/ /                                      {RS}
{DM}       \\____________/                                       {RS}"""
    return art + _logo(R, RE, W) + _tagline(R, W, "Every target tells a story.")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 4 — Wolf Head Geometric / Diamond style
# ═════════════════════════════════════════════════════════════════════════════
def banner_4():
    art = f"""
{DM}                     ___________                           {RS}
{M}                  __/     ^     \\__                        {RS}
{M}               __/   /\\  /|\\  /\\   \\__                    {RS}
{M}              /   __/  \\/   \\/  \\__   \\                   {RS}
{MA}             /   /  ◈  /     \\  ◈  \\   \\                  {RS}
{MA}            |   / __  / \\ ^ / \\  __ \\   |                 {RS}
{MA}            |  / /  \\/ /\\ | /\\ \\ /  \\ \\  |               {RS}
{W}            | | | /\\ \\/  \\|/  \\/ /\\ | | |                {RS}
{W}            | | |/  \\ \\__/|\\__/ /  \\| | |                {RS}
{W}             \\  \\ \\__/ \\ _ | _ / \\__/ /  /               {RS}
{W}              \\  \\  \\__/  \\|/  \\__/  /  /                {RS}
{C}               \\  \\   \\____|____/   /  /                  {RS}
{C}                \\  \\__/ /  |  \\ \\__/  /                   {RS}
{C}                 \\____ /   |   \\ ____/                    {RS}
{CY}                       \\   |   /                           {RS}
{DM}                        \\__|__/                            {RS}"""
    return art + _logo(M, MA, W) + _tagline(M, W, "Intelligence is the sharpest weapon.")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 5 — Wolf + Moon  (howling at full moon)
# ═════════════════════════════════════════════════════════════════════════════
def banner_5():
    art = f"""
{DM}                   * .  . *  .  . * .  . *                 {RS}
{Y}               .        _____        .                      {RS}
{Y}            .          /     \\          .                   {RS}
{Y}           *          |  ( ) |          *                   {RS}
{Y}           .          |       |          .                  {RS}
{Y}            .          \\_____/          .                   {RS}
{DM}               .    *   .   .   *    .                      {RS}
{W}                    /\\    /\\                               {RS}
{W}                   /  \\  /  \\                              {RS}
{W}                  / ◈  \\/  ◈ \\                            {RS}
{C}                 /  ___/\\___  \\                            {RS}
{C}                |  / /\\ /\\ \\  |                           {RS}
{C}                | | /  X  \\ | |                            {RS}
{B}                |  \\ \\/_\\/ /  |                           {RS}
{B}                 \\ /\\  ^  /\\ /                            {RS}
{B}                  X  \\ | /  X                              {RS}
{BL}                 / \\  \\|/  / \\                            {RS}
{DM}                /___\\___|___/___\\                          {RS}"""
    return art + _logo(Y, W, C) + _tagline(Y, W, "Howling at your targets since v1.0")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 6 — Cyber Wolf  (digital / matrix aesthetic)
# ═════════════════════════════════════════════════════════════════════════════
def banner_6():
    art = f"""
{DM}  01001100 01001111 01001110 01000101 01010111 01001111 01001100 01000110{RS}
{G}
{GR}    ╔══╦═══════════════╦══╗                                  {RS}
{G}    ║  ║  /\\   ^   /\\  ║  ║                                  {RS}
{G}    ║  ║ /  \\ /_\\ /  \\ ║  ║                                  {RS}
{G}    ╠══╬/  ◈ \\ | / ◈  \\╬══╣                                  {RS}
{G}    ║  ║\\    \\_|_/    /║  ║                                  {RS}
{GR}   ║  ║ \\  / _|_ \\  / ║  ║                                  {RS}
{GR}   ║  ║  \\/ /   \\ \\/  ║  ║                                  {RS}
{GR}   ╠══╬──/  \\___/  \\──╬══╣                                  {RS}
{W}    ║  ║ / /\\ _|_ /\\ \\ ║  ║                                  {RS}
{W}    ║  ║/ /  V | V  \\ \\║  ║                                  {RS}
{W}    ╠══╬ /    \\|/    \\ ╬══╣                                  {RS}
{W}    ║  ║/      |      \\║  ║                                  {RS}
{C}    ╚══╩═══════|═══════╩══╝                                  {RS}
{DM}              |   |                                          {RS}
{DM}  01110000 01110010 01101111 01101010 01100101 01100011 01110100{RS}"""
    return art + _logo(G, GR, W) + _tagline(G, W, "root@projectz:~# ./hunt --target world")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 7 — Fierce Wolf  (close-up face, sharp fangs)
# ═════════════════════════════════════════════════════════════════════════════
def banner_7():
    art = f"""
{DM}
{R}            /\\                    /\\                        {RS}
{R}           /  \\__________________/  \\                       {RS}
{R}          / /\\ \\                / /\\ \\                     {RS}
{RE}         / /  \\ \\  /\\    /\\  / /  \\ \\                    {RS}
{RE}        | /  ◉ \\ \\/ /\\  /\\ \\/ / ◉  \\ |                  {RS}
{RE}        |/  ___ \\/  \\/  \\/  \\/  ___  \\|                  {RS}
{W}         |  /   \\/\\  /\\  /\\  /\\/   \\  |                  {RS}
{W}         | |  /\\ \\ \\/ /  \\ \\/ / /\\ | |                  {RS}
{W}         | |  \\ \\ X  /    \\  X / / | |                   {RS}
{W}         |  \\  \\ / \\/      \\/ \\ /  /  |                  {RS}
{C}          \\  \\  X   \\  /\\  /   X  /  /                   {RS}
{C}           \\ / / \\   \\/ \\/ /   / \\ / /                   {RS}
{C}            X /   \\__/\\__/\\__/   \\ X                      {RS}
{C}           / X  /\\  \\    /  /\\   X \\                      {RS}
{CY}          /  \\  \\/  /\\  /\\ \\/  /  \\                      {RS}
{DM}         /____\\____/  \\/  \\____/____\\                     {RS}"""
    return art + _logo(R, RE, W) + _tagline(R, W, "Fear the wolf who works in silence.")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 8 — Wolf Pack  (multiple wolves silhouette)
# ═════════════════════════════════════════════════════════════════════════════
def banner_8():
    art = f"""
{DM}       * .   . *    . *  .   * .  .   * .   . * .          {RS}
{BL}                                    /\\                      {RS}
{BL}               /\\              /\\  /  \\  /\\                {RS}
{B}              /  \\    /\\       /  \\/    \\/  \\              {RS}
{B}     /\\      / ◈  \\  /  \\    / ◈  \\  ◈  \\ /\\            {RS}
{W}    /  \\    /  /\\  \\/  ◈ \\  /  __  \\  /\\ \\/  \\          {RS}
{W}   / ◈  \\  |  \\ \\ /\\  / \\ |  / /\\  \\/  / /  ◈ \\        {RS}
{W}  /  /\\  \\ | /\\ X  \\ /   \\| | / \\ X  / /  /    \\       {RS}
{C} |  / \\ \\ \\|/  / \\  X    /  |/   / \\ / / /  /\\  |      {RS}
{C} | /   \\ \\/   /   \\/  \\ /   |   /   X   \\ /  \\ \\ |     {RS}
{C} |/     \\  \\_/     \\   X    |  /   / \\   /\\    \\/ |     {RS}
{CY}|       \\___|      /\\ / \\   | /   /   \\ /  \\      |     {RS}
{DM}|            \\____/  X   \\__|/___/     X    \\_____|      {RS}
{DM}|_____________\\__/ \\_/ \\_/ \\/__/______/ \\___\\______|    {RS}"""
    return art + _logo(B, W, C) + _tagline(B, W, "Alone you scout — together you conquer.")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 9 — Wolf Skull  (dark / gothic style)
# ═════════════════════════════════════════════════════════════════════════════
def banner_9():
    art = f"""
{DM}
{MA}              /\\_________/\\                               {RS}
{M}             /  /\\  ___  /\\ \\                             {RS}
{M}            /  / /\\/ _ \\/\\ \\ \\                           {RS}
{M}           /  / /  \\_X_/  \\ \\ \\                          {RS}
{MA}          |  | /  ◈   ◈  \\ | |                           {RS}
{MA}          |  |/  _/\\_/\\_  \\| |                           {RS}
{W}          |  / /\\/  ^  \\/\\ \\ |                           {RS}
{W}          | | |  \\ _|_ / | | |                            {RS}
{W}          | | |___\\   /___| | |                           {RS}
{W}          |  \\ /  /   \\  \\ /  |                          {RS}
{C}          |   X  / /|\\ \\ X   |                            {RS}
{C}          |  / \\/  |||  \\ \\/\\ |                          {RS}
{C}          | / /\\  /|^|\\  /\\ \\ |                          {RS}
{CY}          |/ /  \\/ _|_ \\/  \\ \\|                          {RS}
{DM}           \\/    \\/(___)\\/ \\ \\/                           {RS}
{DM}                 /__|__\\                                   {RS}"""
    return art + _logo(M, MA, W) + _tagline(M, W, "Death to script kiddies.")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 10 — Minimal Wolf Eyes  (stealth / night mode)
# ═════════════════════════════════════════════════════════════════════════════
def banner_10():
    art = f"""
{DM}
{DM}   · · · · · · · · · · · · · · · · · · · · · · · · · · ·   {RS}
{DM}                                                            {RS}
{DM}                                                            {RS}
{BL}                         /\\ /\\                             {RS}
{B}                        /  X  \\                            {RS}
{W}                       /  ◈ ◈  \\                           {RS}
{W}                      /   \\_/   \\                          {RS}
{W}                     / __/   \\__ \\                         {RS}
{C}                    / /  / | \\  \\ \\                        {RS}
{C}                   / / _/  |  \\_ \\ \\                       {RS}
{C}                  / / /   /|\\ \\  \\ \\ \\                    {RS}
{CY}                 /_/_/___/ | \\___\\_\\_\\                    {RS}
{DM}                          /|\\                               {RS}
{DM}                         / | \\                              {RS}
{DM}                        /  |  \\                             {RS}
{DM}   · · · · · · · · · · · · · · · · · · · · · · · · · · ·   {RS}"""
    return art + _logo(BL, W, C) + _tagline(BL, W, "You can't see me. I can see everything.")


# ═════════════════════════════════════════════════════════════════════════════
#  REGISTRY + RANDOM PICKER
# ═════════════════════════════════════════════════════════════════════════════
BANNERS = [
    banner_1, banner_2, banner_3, banner_4, banner_5,
    banner_6, banner_7, banner_8, banner_9, banner_10,
]

BANNER_NAMES = [
    "Howling Wolf in Circle",
    "Side Profile Tattoo Wolf",
    "Tribal Minimalist Wolf",
    "Geometric Diamond Wolf",
    "Wolf Howling at Moon",
    "Cyber Matrix Wolf",
    "Fierce Close-up Wolf",
    "Wolf Pack Silhouette",
    "Gothic Wolf Skull",
    "Stealth Wolf Eyes",
]


def get_random_banner() -> str:
    """Return a random banner string. Called on every framework startup."""
    return random.choice(BANNERS)()


def get_banner(n: int) -> str:
    """Return a specific banner by number (1-10)."""
    return BANNERS[(n - 1) % len(BANNERS)]()


def list_banners():
    """Print the banner index."""
    print(f"\n{C}  ProjectZ Banner Collection  ({len(BANNERS)} banners){RS}\n")
    for i, name in enumerate(BANNER_NAMES, 1):
        print(f"  {Y}{i:>2}.{RS} {name}")
    print()


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 11 — Shadow Spy
# ═════════════════════════════════════════════════════════════════════════════
def banner_11():
    art = f"""
{DM}         .                                                   .  {RS}
{DM}        / \\                                                 / \\ {RS}
{B}       / spy\\    __________________________________________/ /  {RS}
{B}      / o_o  \\  |  ______   ______   ______   ______      |/   {RS}
{W}     /___/ \\__\\ | |  [ ] | | >_<  | | ____ | | [::] |    |    {RS}
{W}         | |    | |______| |______| |______| |______|    |    {RS}
{W}         | |    |__________________________________________|    {RS}
{C}      ___| |___          SURVEILLANCE  ACTIVE                   {RS}
{C}     /    |    \\         [IIIIIIIIIIIIIIIII.......]  78%        {RS}
{C}    /   __|__   \\        TARGET  ACQUIRED  . . .               {RS}
{C}   |   /     \\   |       SCANNING NETWORK  . . .               {RS}
{B}   |  | (.) (.) |  |     INTEL  HARVESTING . . .               {RS}
{B}   |   \\  ^  /   |                                              {RS}
{B}    \\   |___|   /       .-------------------.                   {RS}
{W}     \\         /        | IP   : xxx.x.x.x  |                  {RS}
{W}      \\_______/         | HOST : [REDACTED] |                  {RS}
{DM}          |              | PORT : 0-65535    |                  {RS}
{DM}          |              '-------------------'                  {RS}"""
    return art + _logo(B, C, W) + _tagline(B, W, "Watch everything. Leave no trace.")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 12 — The Hunter Wolf (pack)
# ═════════════════════════════════════════════════════════════════════════════
def banner_12():
    art = f"""
{DM}                              ___                             {RS}
{B}                           __/   \\__                          {RS}
{B}              /\\          /  \\   /  \\          /\\            {RS}
{B}             /  \\        / /\\ \\ / /\\ \\        /  \\          {RS}
{W}            / /\\ \\      / /  \\_X_/  \\ \\      / /\\ \\        {RS}
{W}           / /  \\_\\    / / __|/ \\|__ \\ \\    /_/  \\ \\       {RS}
{W}          / /  ◈  \\   / / /  |   |  \\ \\ \\  / /  ◈  \\      {RS}
{C}         /_/        \\ /_/ / /\\|   |/\\ \\ \\_\\/_/         \\_ {RS}
{C}                    |   / /  \\   /  \\ \\   |                 {RS}
{C}                    |  / / __\\ / /__\\ \\  |                  {RS}
{CY}                    | | | |  | X |  | | | |                  {RS}
{CY}                    |  \\ \\ \\/ / \\ \\/ / /  |                {RS}
{CY}                     \\  \\_\\  /   \\  /_/  /                 {RS}
{DM}                      \\      \\   /      /                   {RS}
{DM}                       \\______\\ /______/                    {RS}
{DM}                               X                              {RS}
{DM}                            __/ \\__                           {RS}
{DM}                           /  HUNT  \\                         {RS}"""
    return art + _logo(B, W, C) + _tagline(B, W, "The pack never misses its target.")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 13 — Hacker Terminal Wolf
# ═════════════════════════════════════════════════════════════════════════════
def banner_13():
    art = f"""
{G}  +----------------------------------------------------------+  {RS}
{G}  |  root@projectz:~# whoami                                 |  {RS}
{GR}  |  > cyberhowler (R.G)                                          |  {RS}
{GR}  |  root@projectz:~# ./projectz --target $TARGET            |  {RS}
{GR}  |  > [*] Initializing OSINT engine . . .                   |  {RS}
{G}  |  > [+] DNS      [IIIIIIIIIIIIIIIIII]  READY              |  {RS}
{G}  |  > [+] WHOIS    [IIIIIIIIIIIIIIIIII]  READY              |  {RS}
{G}  |  > [+] SHODAN   [IIIIIIIIIIIIIIIIII]  READY              |  {RS}
{G}  |  > [!] CAUTION: You are being logged                      |  {RS}
{G}  +----------------------------------------------------------+  {RS}
{W}        /\\_____/\\                 /\\_____/\\                  {RS}
{W}       /  ◈   ◈  \\               /  ◈   ◈  \\                {RS}
{W}      (   __/ \\__  )             (   __/ \\__  )              {RS}
{C}       )  |     |  (               )  |     |  (              {RS}
{C}      (   |     |   )             (   |     |   )             {RS}
{C}      (__(___)(_____)             (__(___)(_____)             {RS}
{G}                         WOLF  x2  ONLINE                    {RS}"""
    return art + _logo(G, GR, W) + _tagline(G, W, "root@projectz:~# ./hunt --target world")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 14 — Night Wolf under Stars
# ═════════════════════════════════════════════════════════════════════════════
def banner_14():
    art = f"""
{DM}                *        .          *                        {RS}
{DM}          .                  *            .                  {RS}
{Y}      *         .    *                *                      {RS}
{Y}             .              .      .            *            {RS}
{DM}                   .   *                    .                {RS}
{DM}       .      *                  .     *                     {RS}
{BL}                           /\\                               {RS}
{BL}                          /  \\           * .               {RS}
{B}             .            / /\\ \\                  .         {RS}
{B}                         / /  \\_\\                           {RS}
{W}             *            |/  ◈  ◈ \\         *              {RS}
{W}              .           |  ___/\\_ |                       {RS}
{W}                           \\  |   | /                        {RS}
{C}                  .         \\| ^ |/          .              {RS}
{C}                             |   |                           {RS}
{C}                        _____|   |_____                      {RS}
{CY}                   ____/    N I G H T    \\____               {RS}
{DM}              ____/          H U N T E R      \\____          {RS}
{DM}         ____/________________________________\\____          {RS}"""
    return art + _logo(BL, W, C) + _tagline(BL, W, "In darkness, data is the only light.")


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER 15 — Ghost Wolf (transparent/stealth recon)
# ═════════════════════════════════════════════════════════════════════════════
def banner_15():
    art = f"""
{DM}        . . . . . . . . . . . . . . . . . . . . . . . .      {RS}
{DM}        .                                             .       {RS}
{DM}        .         @@@@@@@@@@@@@@@@@@@@@@              .       {RS}
{BL}        .       @@@@@@@@@@@@@@@@@@@@@@@@@@            .       {RS}
{BL}        .      @@@@  /\\  @@@@@@@@  /\\  @@@@           .       {RS}
{B}        .     @@@@ /^^\\  @@@@@@@@ /^^\\  @@@@          .       {RS}
{B}        .     @@@  | ◈ | @@@@@@@ | ◈ |  @@@          .       {RS}
{W}        .     @@@  \\____/ @@@@@@@ \\____/ @@@          .       {RS}
{W}        .     @@@@  \\/   @@@@@@@@  \\/   @@@@          .       {RS}
{W}        .      @@@@  /\\ @@@@@@@@@@ /\\  @@@@           .       {RS}
{C}        .       @@@@ /  \\@@@@@@@@/  \\ @@@@            .       {RS}
{C}        .        @@ /    \\@@@@@@/    \\ @@             .       {RS}
{C}        .          /  /\\  \\@@@@/  /\\  \\               .       {RS}
{CY}        .         /  /  \\  \\/  /  \\  \\               .       {RS}
{DM}        .        /__/    \\____/    \\__\\               .       {RS}
{DM}        .                                             .       {RS}
{DM}        . . . . . . . . . . . . . . . . . . . . . . . .       {RS}"""
    return art + _logo(BL, C, W) + _tagline(BL, W, "You can't trace what you can't see.")


# ── Update registry ───────────────────────────────────────────────────────────
BANNERS.extend([banner_11, banner_12, banner_13, banner_14, banner_15])
BANNER_NAMES.extend([
    "Shadow Spy",
    "The Hunter Wolf",
    "Hacker Terminal Wolf",
    "Night Wolf under Stars",
    "Ghost Wolf",
])
