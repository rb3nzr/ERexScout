import tables, nre, strformat, strutils, terminal

#[
  Add a new group of expressions below
  Add the group to the allGroups table

  ex: erex_scout -p=1234 -e -t=7.3 -g=test_general
]#

type
  LabeledRegex* = tuple
    label: string
    pattern: Regex

const GeneralTest* = {
  "guid": r"[{]?[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}[}]?",
  #"base64": r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
  "b2": r"(?s:[A-Za-z0-9+/=\s]{10,})?",
  "base64_2": r"[A-Za-z0-9+/]{10,}(?:={0,2})?",
  "ipv4": r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b",
  "email": r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",
  "mail_to": r"(?i)(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+",
  #"https": r"https?:\/\/(?:www\.)?[\w\.]{2,256}\/?(?:[\w/]+)?(?:\?[^#]+)?(?:#.+)?$",
  #"domain": r"\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b",
  "url_general": r"(?:http[s]?:\/\/.)?(?:www\.)?[-a-zA-Z0-9@%._\+~#=]{2,256}\.[a-z]{2,6}\b(?:[-a-zA-Z0-9@:%_\+.~#?&\/\/=]*)",
  "ftp": r"(?i)(ftp)://([A-Z0-9][A-Z0-9_-]*(?:.[A-Z0-9][A-Z0-9_-]*)+):?(d+)?",
  "mac_address": r"(?i)([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",
  "web_socket": r"(ws:\/\/|wss:\/\/)",
  "ms_ie_user_agent": r"(?i)Mozilla\/.*\((.*MSIE.*|Windows.*Trident\/.*)\)?",
  "file_path": r"([A-Za-z]):\\((?:[A-Za-z\d][A-Za-z\d\- \x27_\(\)~]{0,61}\\?)*[A-Za-z\d][A-Za-z\d\- \x27_\(\)]{0,61})(\.[A-Za-z\d]{1,6})?"
}.toOrderedTable()

const WinMemTest* = {
  "32bit_pe": r"PE\x00\x00\x4c\x01.{18}\x0b[\x01\x02]",
  "64bit_pe": r"PE\x00\x00\x64\x86.{18}\x0b[\x01\x02]",
  "path": r"(?i)(?:\\\\\?\\)?[A-Za-z]:\\.+",
  "pipe": r"\\pipe\\"
}.toOrderedTable()

const allGroups* = {
  "test_general": (desc: "Some common patterns. email/url/domain/ip etc.", rex: GeneralTest),
  "test_win_mem": (desc: "Testing block for process memory in Windows", rex: WinMemTest)
}.toTable()

proc getGroup*(name: string): OrderedTable[string, string] =
  let lowered = name.toLower()
  if lowered in allGroups:
    return allGroups[lowered].rex
  else:
    styledEcho styleBright,bgYellow,fgBlack,&"[!] Regex group '{name}' not found"
    quit(0)
