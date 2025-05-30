import std/[os, strutils, sequtils, streams, nre, tables, math, json, sha1, times, terminal, logging]
from strformat import `&`

import regex
import magic
import rexes

let fLog = newFileLogger("erex_scout.log", levelThreshold=lvlAll, fmtStr="$time $levelname: $msg")
addHandler(fLog)

proc toPrintableAscii(buff: string): string =
  for ch in buff:
    if ch in {' '..'~'}: result.add(ch)
    else: result.add('.')

proc stripNulls(raw: string): string =
  var i = 0
  while i < raw.len:
    result.add(raw[i])
    i += 2

proc checkFileMagic(fStream: Stream): string = 
  for (description, pattern) in FileSignatures.pairs:
    fStream.setPosition(0)
    var bPattern = parseHexStr(pattern)
    let header = fStream.readStr(bPattern.len)
    if header == bPattern: return description
  "Unknown"

proc getEntropy(data: string): float {.inline.} =
  if data.len == 0: return 0.0
  var counts = initCountTable[char]()
  for c in data: counts.inc(c)
  for count in counts.values:
    let p = count / data.len
    result -= p * log2(p)

proc getEntropyChunks(fileName: string, fStream: Stream, chunkSize: int, threshold: float): seq[JsonNode] = 
  var offset = 0
  while not fStream.atEnd():
    let chunk = fStream.readStr(chunkSize)
    if chunk.len == 0: break

    let entropy = getEntropy(chunk)
    if entropy >= threshold:
      let peek = toPrintableAscii(chunk[0 ..< min(chunk.len, 120)])
      styledEcho styleBright,fgGreen,&"[+] High entropy chunk in: ",resetStyle,fgWhite,&"{fileName}"
      styledEcho styleBright,fgWhite,"  | offset: ",resetStyle,fgCyan,&"0x{offset:08X}"
      styledEcho styleBright,fgWhite,"  | entropy: ",resetStyle,fgRed,&"{entropy:.2f}"
      styledEcho styleBright,fgWhite,"  | peek: ",resetStyle,fgYellow,&"{peek}\n"

      result.add(%*{
        "entropy": entropy,
        "offset": &"0x{offset:X}",
        "peek": peek,
        "chunk": chunk.toHex
      })
    offset += chunkSize 

proc scanFile(fileName: string, rexes: seq[LabeledRegex], chkEntropy: bool, threshold: float, chunkSize: int): JsonNode =
  var fStream = newFileStream(fileName, fmRead)
  defer: fStream.close()
  if fStream == nil: return nil

  let sigMatch = checkFileMagic(fStream)
  fStream.setPosition(0) 

  let 
    sBuff = fStream.readAll()
    peek = toPrintableAscii(sBuff[0 ..< min(sBuff.len, 120)])

  var 
    entropy: float = 0.0
    entropyChunks = newSeq[JsonNode]()

  if chkEntropy:
    entropyChunks = getEntropyChunks(fileName, fStream, chunkSize, threshold)
    entropy = getEntropy(sBuff)
  
  let
    fileHash   = $secureHash(fileName)
    fileInfo   = getFileInfo(fileName)
    isHidden   = isHidden(fileName)
    fileSize   = float64(getFileSize(fileName)) / 1024
    created    = fileInfo.creationTime.format("yyyy-MM-dd HH:mm:ss")
    lastWrite  = fileInfo.lastWriteTime.format("yyyy-MM-dd HH:mm:ss")
    lastAccess = fileInfo.lastAccessTime.format("yyyy-MM-dd HH:mm:ss")

  if entropy >= threshold:
    styledEcho styleBright,fgGreen,"[+] High entropy file: ",resetStyle,fgWhite,&"{fileName}"
    styledEcho styleBright,fgWhite,"  | entropy: ",resetStyle,fgRed,&"{entropy:.2f}"
    styledEcho styleBright,fgWhite,"  | size: ",resetStyle,fgCyan,&"{fileSize:.2f} KB"
    styledEcho styleBright,fgWhite,"  | created: ",resetStyle,fgMagenta,&"{created}"
    styledEcho styleBright,fgWhite,"  | last write: ",resetStyle,fgMagenta,&"{lastWrite}"
    styledEcho styleBright,fgWhite,"  | perms: ",resetStyle,fgBlue,&"{fileInfo.permissions}"
    styledEcho styleBright,fgWhite,"  | peek: ",resetStyle,fgYellow,&"{peek}\n"

  var fileNode = %*{
    "file_name": fileName,
    "signature_match": sigMatch,
    "file_size": &"{fileSize:.2f} KB",
    "link_count": fileInfo.linkCount,
    "is_hidden": isHidden,
    "last_access": lastAccess,
    "last_write": lastWrite,
    "created": created,
    "permissions": $fileInfo.permissions,
    "file_entropy": &"{entropy:.2f}",
    "file_hash": fileHash,
    "peek": peek,
    "high_entropy_sections": entropyChunks, 
    "regex_matches": newJArray()
  }
  
  const wsrex = re2(r"(?:[\x20-\x7E]\x00){4,}", {regexArbitraryBytes})
  var wideMap  = initTable[string, seq[int]]()

  #[ dumb way of getting wide strings ]#
  try:
    let fContent = readFile(fileName)
    for wsMatch in findAll(fContent, wsrex):
      let 
        wsOffset = wsMatch.boundaries.a
        ws = stripNulls(fContent[wsMatch.boundaries])     

      if not wideMap.hasKey(ws):
        wideMap[ws] = @[]
      wideMap[ws].add(wsOffset)
    
    for (label, rex) in rexes:
      for strVal, offsets in wideMap:
        let cwMatch = find(strVal, rex)
        if cwMatch.isSome:
          for offset in offsets:
            let peek = strVal[0 ..< min(strVal.len, 50)]

            let wMatchNode = %*{
              "label": label,
              "type": "wide",
              "offset": &"0x{offset:08X}",
              "match": strVal
            }
            fileNode["regex_matches"].add(wMatchNode)

            fLog.log(lvlInfo, &"[ {label} ] wide match in {fileName}")
            styledEcho styleBright,fgGreen,&"[ {label} ] match in ",resetStyle,fgWhite,&"{fileName}"
            styledEcho styleBright,fgWhite,"  | offset: ",resetStyle,fgCyan,&"0x{offset:08X}"
            styledEcho styleBright,fgWhite,"  | peek: ",resetStyle,fgYellow,&"{peek}\n"

    for (label, rex) in rexes:
      for match in fContent.findIter(rex):
        let 
          matchAddr = match.matchBounds.a 
          peek = match.match[0 ..< min(match.match.len, 50)]

        let aMatchNode = %*{
          "label": label,
          "type": "ascii",
          "offset": &"0x{matchAddr:08X}",
          "match": match.match
        }
        fileNode["regex_matches"].add(aMatchNode)

        fLog.log(lvlInfo, &"[ {label} ] ascii match in {fileName}")
        styledEcho styleBright,fgGreen,&"[ {label} ] match in ",resetStyle,fgWhite,&"{fileName}"
        styledEcho styleBright,fgWhite,"  | offset: ",resetStyle,fgCyan,&"0x{matchAddr:X}"
        styledEcho styleBright,fgWhite,"  | peek: ",resetStyle,fgYellow,&"{peek}\n"

  except IOError as err:
    fLog.log(lvlError, &"IOError reading: {fileName} | {err.msg}")
    return nil
  return fileNode
    
proc scanFilesRec*(path: string, rexes: seq[LabeledRegex], chkEntropy: bool, threshold: float, chunkSize: int): seq[JsonNode] =
  fLog.log(lvlInfo, &"--------------- [ Start for {path} ] ----------------")
  result = newSeq[JsonNode]()
  for entry in walkDirRec(path):
    let scanRes = scanFile(entry, rexes, chkEntropy, threshold, chunkSize)
    if not scanRes.isNil:
      result.add(scanRes)

proc scanFiles*(path: string, rexes: seq[LabeledRegex], chkEntropy: bool, threshold: float, chunkSize: int): seq[JsonNode] =
  fLog.log(lvlInfo, &"--------------- [ Start for {path} ] ----------------")
  result = newSeq[JsonNode]()
  for entry in walkDir(path):
    if entry.kind == pcFile:
      let scanRes = scanFile(entry.path, rexes, chkEntropy, threshold, chunksize)
      if not scanRes.isNil:
        result.add(scanRes)
