import core/rexes
import core/files
import core/memory
import cligen 
import std/[
  os, strutils, streams, strformat, nre, json, tables, terminal
]

proc main(
  pid: int = 0, 
  path: string = "",
  recurse: bool = false,
  entropy: bool = false,
  threshold: float = 6.7,
  chunkSize: int = 120,
  listGroups: bool = false,
  rexGroup: string = "",
  userRex: string = "",
  outputPath: string = ""
) = 
  if listGroups:
    styledEcho styleBright,fgMagenta,"---------- [ Rex Groups ] ----------"
    for label, (desc, _) in allGroups:
      styledEcho styleBright,fgGreen,&"-> {label}: ",resetStyle,fgCyan,&"{desc}"
    quit(0)

  if pid == 0 and path == "":
    styledEcho styleBright,bgYellow,fgBlack,"[!] Either -p/--pid or -d/--path is required"
    styledEcho styleBright,fgGreen,"[>] -h for full options"
    quit(0)
  if userRex == "" and rexGroup == "":
    styledEcho styleBright,bgYellow,fgBlack,"[!] One of -u/--user-rex or -r/--rex-group is required"
    quit(0)
  
  var rexes: seq[tuple[label: string, pattern: Regex]] 
  if rexGroup != "":
    let groupTable = getGroup(rexGroup)
    for key, pattern in groupTable.pairs:
      rexes.add((key, re(pattern)))
  else:
    rexes.add(("user_regex", re(userRex)))

  if pid != 0:
    styledEcho styleBright,bgYellow,fgBlack,"[>] Scanning.."
    let procRes: seq[JsonNode] = scanProcessMemory(pid, rexes, entropy, threshold)
    if outputPath != "":
      let mode = if fileExists(outputPath): fmAppend else: fmWrite 
      let f = open(outputPath, mode)
      defer: f.close()

      var rootNode = newJObject()
      rootNode["Process-" & $pid] = %procRes
      f.writeLine($rootNode)
    else:
      styledEcho styleBright,bgYellow,fgBlack,"[!] No output path selected"
  
  if path != "":
    if dirExists(path):
      styledEcho styleBright,bgYellow,fgBlack,"[>] Scanning.."
      var fileRes: seq[JsonNode]
      if recurse:
        fileRes = scanFilesRec(path, rexes, entropy, threshold, chunkSize)
      else:
        fileRes = scanFiles(path, rexes, entropy, threshold, chunkSize)

      if outputPath != "":
        let mode = if fileExists(outputPath): fmAppend else: fmWrite 
        let f = open(outputPath, mode)
        defer: f.close()

        var rootNode = newJObject()
        rootNode["RootDir-" & path] = %fileRes 
        f.writeLine($rootNode)
      else:
        styledEcho styleBlink,bgBlue,fgRed,"[!] No output path selected"
    else:
      styledEcho styleBright,bgYellow,fgBlack,"[!] Path not found"

when isMainModule:
  dispatch(main, help = {
    "pid": "Process to scan",
    "path": "Directory path for file scanning",
    "recurse": "Recursively process files from the given directory path",
    "entropy": "Check entropy",
    "threshold": "Entropy threshold",
    "chunk-size": "Size of chunks for entropy checks (files only)",
    "list-groups": "List the available regex groups",
    "rex-group": "Pass the regex group to use",
    "user-rex": "Provide a single regex to use",
    "output-path": "JSON output file path (appends)"
  }, short = {"path": 'd', "rex-group": 'g'})
