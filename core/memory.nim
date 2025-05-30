import std/[os, strutils, math, nre, tables, json, terminal, logging]
from strformat import `&`

import rexes
import regex

when defined(windows):
  import winim
  from sequtils import mapIt
  from parseutils import parseHex
else:
  import std/posix
  import ptrace
  import ptrace/syscall 
  import parseutils 
  import sequtils

let fLog = newFileLogger("erex_scout.log", levelThreshold=lvlAll, fmtStr="$time $levelname: $msg")
addHandler(fLog)
 
proc getEntropy(data: openArray[byte]): float {.inline.} =
  if data.len == 0: return 0.0
  var counts = initCountTable[byte]() 
  for b in data: counts.inc(b)
  for count in counts.values:
    let p = count / data.len
    result -= p * log2(p)

proc stripNulls(raw: string): string =
  var i = 0
  while i < raw.len:
    result.add(raw[i])
    i += 2
    
proc parseHexStrToUInt64(s: string): uint64 = 
  var val: uint64 
  discard parseHex(s.strip(chars={ '0', 'x' }), val)
  result = val 

proc toPrintable(buff: string): string =
  for ch in buff:
    if ch in {' '..'~'}: result.add(ch)
    else: result.add('.')

proc btoPrintable(buff: seq[byte]): string =
  result = newStringOfCap(buff.len)
  for b in buff:
    let c = chr(int(b))  
    if c in {' '..'~'}: result.add(c)
    else: result.add('.')

when defined(windows):
  const
    EXCEPTION_MAXIMUM_PARAMETERS = 15
    SEH_END_MARKER_32 = 0xFFFFFFFF'u32
    SEH_END_MARKER_64 = 0xFFFFFFFFFFFFFFFF'u64

  type
    EXCEPTION_REGISTRATION_RECORD_32* {.packed.} = object
      Next*:    uint32
      Handler*: uint32

    EXCEPTION_REGISTRATION_RECORD_64* {.packed.} = object
      Next*:    uint64
      Handler*: uint64

  type
    CLIENT_ID* {.pure.} = object
      UniqueProcess*: HANDLE
      UniqueThread*:  HANDLE

    THREAD_BASIC_INFORMATION* {.pure.} = object
      ExitStatus*:     NTSTATUS
      TebBaseAddress*: PVOID
      ClientId*:       CLIENT_ID
      AffinityMask*:   KAFFINITY
      Priority*:       KPRIORITY
      BasePriority*:   KPRIORITY

  proc memberToStr(m: DWORD): string =
    case m
    of PAGE_EXECUTE:           "EXECUTE"         
    of PAGE_EXECUTE_READ:      "EXECUTE_READ"      
    of PAGE_EXECUTE_READWRITE: "EXECUTE_READWRITE" 
    of PAGE_EXECUTE_WRITECOPY: "EXECUTE_WRITECOPY" 
    of PAGE_NOACCESS:          "NOACCESS"          
    of PAGE_READONLY:          "READONLY"          
    of PAGE_READWRITE:         "READWRITE"         
    of PAGE_WRITECOPY:         "WRITECOPY"
    of MEM_COMMIT:             "COMMIT"
    of MEM_FREE:               "FREE"
    of MEM_RESERVE:            "RESERVE"
    of MEM_IMAGE:              "IMAGE"
    of MEM_MAPPED:             "MAPPED"
    of MEM_PRIVATE:            "PRIVATE"        
    else: $m
  
  proc priorityToStr(m: DWORD): string = 
    case m 
    of THREAD_PRIORITY_NORMAL:        "NORMAL"
    of THREAD_PRIORITY_ABOVE_NORMAL:  "ABOVE_NORMAL"
    of THREAD_PRIORITY_BELOW_NORMAL:  "BELOW_NORMAL"
    of THREAD_PRIORITY_HIGHEST:       "HIGHEST"
    of THREAD_PRIORITY_IDLE:          "IDLE"
    of THREAD_PRIORITY_LOWEST:        "LOWEST"
    of THREAD_PRIORITY_TIME_CRITICAL: "TIME_CRITICAL"
    else: $m
  
  proc getMappedPath(hProc: HANDLE, modBase: PVOID): string = 
    const MAX = 1024
    var buffer: array[MAX, WCHAR]
    zeroMem(addr buffer[0], sizeof(buffer))
    let len = GetMappedFileNameW(hProc, modBase, buffer[0].addr, MAX.DWORD)
    if len == 0: return ""
    result = $cast[WideCString](buffer.addr)

  proc getThreads(pid: DWORD): seq[DWORD] =
    var
      hSnapshot: HANDLE 
      threadEntry: THREADENTRY32

    threadEntry.dwSize = cast[DWORD](sizeof(THREADENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    Thread32First(hSnapshot, &threadEntry)

    while Thread32Next(hSnapshot, &threadEntry):
      if threadEntry.th32OwnerProcessID == pid:
        result.add(threadEntry.th32ThreadID)

  proc isProcess32(hProc: HANDLE): bool = 
    var isWow64: WINBOOL 
    if IsWow64Process(hProc, addr isWow64) != 0:
      result = isWow64 != 0
    else: fLog.log(lvlError, "IsWow64Process failed")

  proc getSEHChain(hProc: HANDLE, exceptionList: PVOID): JsonNode =
    var is32: bool = isProcess32(hProc)
    var
      depth = 0
      isCorrupted = false
      sehChain: seq[JsonNode]
      currentAddr = cast[uint64](exceptionList) 
      sehEndMarker = if is32: SEH_END_MARKER_32.uint64 else: SEH_END_MARKER_64
      recordSize = if is32: sizeof(EXCEPTION_REGISTRATION_RECORD_32) else: sizeof(EXCEPTION_REGISTRATION_RECORD_64)
    
    while currentAddr != 0 and currentAddr != sehEndMarker and depth < 100:
      var recordBytes: array[16, byte] # max size for 64bit record
      var bytesRead: SIZE_T 

      if ReadProcessMemory(hProc, cast[LPCVOID](currentAddr), &recordBytes[0], recordSize, &bytesRead) == 0:
        sehChain.add(%*{
          "error": &"Failed to read SEH record at 0x{currentAddr:016X}"
        })
        fLog.log(lvlError, &"Failed to read SEH record at 0x{currentAddr:016X}")
        isCorrupted = true 
        break 
      
      if bytesRead != recordSize:
        sehChain.add(%*{
          "error": &"Partial read at 0x{currentAddr:016X}",
          "bytes": bytesRead,
          "expected": recordSize
        })
        fLog.log(lvlInfo, &"Partial SEH record read at 0x{currentAddr:016X}")
        isCorrupted = true 
        break 
      
      var nextAddr, handlerAddr: uint64
      if is32: 
        let record = cast[ptr EXCEPTION_REGISTRATION_RECORD_32](addr recordBytes[0])
        nextAddr = record.Next.uint64 
        handlerAddr = record.Handler.uint64
      else:
        let record = cast[ptr EXCEPTION_REGISTRATION_RECORD_64](addr recordBytes[0])
        nextAddr = record.Next 
        handlerAddr = record.Handler

      let handlerModule = getMappedPath(hProc, cast[PVOID](handlerAddr))

      sehChain.add(%*{
        "address": &"0x{currentAddr:016X}",
        "handler": &"0x{handlerAddr:016X}",
        "handler_module": handlerModule,
        "next": &"0x{nextAddr:016X}"
      })

      currentAddr = nextAddr
      depth.inc 

      if depth >= 100:
        sehChain.add(%*{"warning": "SEH chain depth limit reached"})
        fLog.log(lvlWarn, "SEH chain depth limit reached")
    
    result = %*{
      "is_corrupted": isCorrupted,
      "chain_length": depth,
      "chain": sehChain,
    }

  proc getThreadDetails(tid: DWORD, hProc: HANDLE): JsonNode =
    let hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid)
    defer: CloseHandle(hThread)
    if hThread == 0:
      styledEcho styleBright,fgRed,bgBlue,&"[X] OpenThread fail | tid: {tid}"
      return %*{"tid": tid, "error": "OpenThread failed"}
    
    var ctxNode = newJObject()
    let suspendCount = SuspendThread(hThread)
    if suspendCount == DWORD(-1):
      styledEcho styleBright,fgRed,bgBlue,&"[X] SuspendThread fail | tid: {tid}"
      return %*{"tid": tid, "error": "SuspendThread failed"}
    
    var ctx: CONTEXT 
    ctx.ContextFlags = CONTEXT_ALL
    if GetThreadContext(hThread, addr ctx) != 0:
      ctxNode = %*{
        "dr0": &"0x{ctx.Dr0:016X}",
        "dr1": &"0x{ctx.Dr1:016X}",
        "dr2": &"0x{ctx.Dr2:016X}",
        "dr3": &"0x{ctx.Dr3:016X}",
        "dr7": &"0x{ctx.Dr7:016X}",
        "flags": &"0x{ctx.EFlags:08X}"
      }
    else:
      let err = GetLastError()
      styledEcho styleBright,fgRed,fgBlue,&"[X] GetThreadContext failed (0x{err:X})"
      ctxNode["error"] = % &"GetThreadContext failed (0x{err:X})"
    
    discard ResumeThread(hThread)

    var startAddr: PVOID
    let priority = priorityToStr(GetThreadPriority(hThread))
    let status = NtQueryInformationThread(hThread, THREADINFOCLASS(9), addr startAddr, ULONG(sizeof(PVOID)), nil)
    if status != 0:
      styledEcho styleDim,fgRed,fgBlue,&"[X] NtQueryInformationThread fail | tid: {tid}"
      return %*{"tid": tid, "error": "NtQueryInformationThread failed"}

    var creationTime, exitTime, kernelTime, userTime: FILETIME
    if GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime, &userTime) == 0:
      return %*{"tid": tid, "error": "GetThreadTimes failed"}

    proc fileTimeToSeconds(ft: FILETIME): float =
      let i64 = (cast[uint64](ft.dwHighDateTime) shl 32 or cast[uint64](ft.dwLowDateTime))
      result = i64.float / 10_000_000.0 

    var 
      exceptionList: PVOID 
      tbi: THREAD_BASIC_INFORMATION

    discard NtQueryInformationThread(hThread, threadBasicInformation, &tbi, DWORD(sizeof(THREAD_BASIC_INFORMATION)), nil)
    let tebAddr = tbi.TebBaseAddress 

    discard ReadProcessMemory(hProc, tebAddr, &exceptionList, sizeof(PVOID), nil)
    let sehInfo = getSEHChain(hProc, exceptionList)

    %*{
      "tid": tid,
      "start_address": &"0x{cast[uint64](startAddr):016X}",
      "user_time": fileTimeToSeconds(userTime),
      "kernel_time": fileTimeToSeconds(kernelTime),
      "creation_time": fileTimeToSeconds(creationTime),
      "priority": priority,
      "context": ctxNode,
      "seh_info": sehInfo
    }

  proc getSeDebug(): bool = 
    var
      luid: LUID
      hToken: HANDLE 
      tokenPrivs: TOKEN_PRIVILEGES

    if (FALSE == OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, addr hToken)):
      fLog.log(lvlError, "OpenProcessToken failed")
      return false 
    if (FALSE == LookupPrivilegeValue(NULL, "SeDebugPrivilege", addr luid)):
      fLog.log(lvlError, "LookupPrivilegeValue error")
      return false
    
    tokenPrivs.PrivilegeCount = 1
    tokenPrivs.Privileges[0].Luid = luid 
    tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED 
    
    if (0 == AdjustTokenPrivileges(hToken, FALSE, addr tokenPrivs, cast[DWORD](sizeof(TOKEN_PRIVILEGES)), cast[PTOKEN_PRIVILEGES](NULL), cast[PDWORD](NULL))):
      fLog.log(lvlError, "AdjustTokenPrivileges error")
      return false 
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED):
      fLog.log(lvlError, "AdjustTokenPrivileges error")
      return false 
    return true 

when defined(linux):
  #[ check entropy on the first 1024 bytes from the stack pointer location ]#
  proc captureStack(pid: int, rsp: uint64, bytes=1024): JsonNode =
    result = newJObject()
    let memPath = "/proc/" & $pid & "/mem"

    try:
      var memFile = open(memPath, fmRead)
      defer: memFile.close()

      memFile.setFilePos(cast[int64](rsp))
      var buffer = newSeq[byte](bytes)
      let bytesRead = memFile.readBuffer(addr buffer[0], bytes)

      result["entropy"] = %getEntropy(buffer[0 ..< bytesRead])
      result["peek"] =  %btoPrintable(buffer[0 ..< min(buffer.len, 120)])
    except Exception as err:
      result["error"] = %(&"error: {err.msg}")

  #[ use ptrace to get the stack ptr and instruction ptr locations ]#
  proc getThreadRegisters(tid: Pid): JsonNode = 
    result = newJObject()
    
    if ptrace(PTRACE_ATTACH, tid, 0.clong, 0.clong) == -1:
      result["error"] = %(&"thread attach failed: {strerror(errno)}")
    
    var status: cint 
    let waited = waitpid(tid, status, 0.cint)
    if waited == -1 or not WIFSTOPPED(status):
      result["error"] = %(&"wait failed: {strerror(errno)}")
      discard ptrace(PTRACE_DETACH, tid, 0.clong, 0.clong)
      return 
    
    var regs: Registers 
    const PTRACE_GETREGS = 12.cint 
    if ptrace(PTRACE_GETREGS, tid, 0.clong, addr regs) == -1:
      result["error"] = %(&"GetRegs failed: {strerror(errno)}")
    else:
      when defined(amd64):
        result["rip"] = %(&"0x{regs.rip:016X}")
        result["rsp"] = %(&"0x{regs.rsp:016X}")

    discard ptrace(PTRACE_DETACH, tid, 0.clong, 0.clong)
    
  proc getThreadDetails(pid: int): seq[JsonNode] = 
    let taskDir = &"/proc/{pid}/task/"
    for tidDir in walkDir(taskDir):
      let tid = extractFilename(tidDir.path).parseInt()
      var tidNode = %*{
        "tid": %tid,
        "ppid": "",
        "name": "",
        "state": "",
        "priority": "",
        "registers": newJNull(),
        "stack": newJNull(),
        "cpu_times": newJNull()
      }

      let status = tidDir.path / "status"
      if fileExists(status):
        try:
          let statusContent = readFile(status)
          for line in statusContent.splitLines():
            let sLine = line.strip()
            if sLine.startsWith("State:"):
              tidNode["state"] = %line.split(':')[1].strip()
            elif sLine.startsWith("PPid:"):
              tidNode["ppid"] = %line.split(':')[1].strip()
        except: discard 
      else:
        fLog.log(lvlDebug, &"Error reading status for thread: {tid}")

      let schedPath = tidDir.path / "sched"
      if fileExists(schedPath):
        try:
          let sched = readFile(schedPath)
          let match = nre.find(sched, nre.re(r"prio\s+:\s+(\d+)"))
          tidNode["priority"] = %match.get.captures[0]
        except: discard 
      else:
        fLog.log(lvlDebug, &"Error reading sched for thread: {tid}")

      let commPath = tidDir.path / "comm"
      if fileExists(commPath):
        tidNode["name"] = %readFile(commPath).strip()

      if geteuid() == 0:
        tidNode["registers"] = getThreadRegisters(tid.Pid)
        let rsp = parseHexInt(tidNode["registers"]["rsp"].getStr())
        tidNode["stack"] = captureStack(pid, rsp.uint64)
      
      let statPath = tidDir.path / "stat"
      if fileExists(statPath):
        try:
          let stat = readFile(statPath)
          let commEnd = stat.find(')')
          let nums = stat[commEnd+2..^1].splitWhitespace()
          tidNode["cpu_times"] = %*{
            "utime": nums[11], # user time (clock ticks)
            "stime": nums[12] # sys time
          }
        except: discard 
      result.add(tidNode)

proc scanProcessMemory*(pid: int, rexes: seq[LabeledRegex], chkEntropy: bool, threshold: float): seq[JsonNode] = 
  when defined(windows):
    fLog.log(lvlInfo, &"--------------- [ Start for PID: {pid} ] ----------------")
    if getSeDebug(): 
      styledEcho styleBright,fgGreen,bgBlue,"[+] SeDebug enabled"
    else: 
      styledEcho styleBright,fgYellow,bgBlack,"[!] SeDebug failed"
      fLog.log(lvlInfo, "SeDebugPrivilege not gained")

    var hProc: HANDLE
    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid.DWORD)
    defer: CloseHandle(hProc)
    if hProc == 0:
      let err = GetLastError()
      styledEcho styleBright,fgRed,bgBlue,&"[X] OpenProcess failed (0x{err:X})"
      fLog.log(lvlError, "OpenProcess failed")
      quit(0)
    
    var 
      currentAddr: PVOID = nil  
      mbi: MEMORY_BASIC_INFORMATION
      threadDetails: seq[JsonNode] = @[] 
    
    let tids = getThreads(pid.DWORD)
    for tid in tids: threadDetails.add(getThreadDetails(tid, hProc))

    while VirtualQueryEx(hProc, currentAddr, addr mbi, sizeof(mbi).DWORD) != 0:
      if mbi.State == MEM_COMMIT and mbi.Protect.ord in {
        PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY
      }.mapIt(it.ord):
      
        var
          bytesRead: SIZE_T 
          buffer = newSeq[byte](mbi.RegionSize)
        
        let 
          regionStart  = cast[uint64](mbi.BaseAddress)
          regionEnd    = regionStart + mbi.RegionSize.uint64
          mProtect     = memberToStr(mbi.Protect)
          mState       = memberToStr(mbi.State)
          mType        = memberToStr(mbi.Type)
          mappedPath   = getMappedPath(hProc, cast[PVOID](mbi.BaseAddress))

        if ReadProcessMemory(hProc, mbi.BaseAddress, addr buffer[0], mbi.RegionSize, addr bytesRead) != 0:
          let peek = bToPrintable(buffer[0 ..< min(buffer.len, 120)])
          var entropy: float = 0.0
          if chkEntropy:
              entropy = getEntropy(buffer[0 ..< bytesRead])
          if entropy >= threshold:
            fLog.log(lvlInfo, &"High entropy region at: 0x{cast[uint64](mbi.BaseAddress):016X}")
            styledEcho styleBright,fgGreen,"[+] High entropy region at: ",resetStyle,fgWhite,&"0x{cast[uint64](mbi.BaseAddress):016X}" 
            styledEcho styleBright,fgCyan,&"  | {mProtect} | {mState} | {mType}"
            styledEcho styleBright,fgWhite,"  | size: ",resetStyle,fgBlue,&"0x{mbi.RegionSize:X}"
            styledEcho styleBright,fgWhite,"  | entropy: ",resetStyle,fgRed,&"{entropy:.2f}"
            styledEcho styleBright,fgWhite,"  | path: ",resetStyle,fgMagenta,&"{mappedPath}"
            styledEcho styleBright,fgWhite,"  | peek: ",resetStyle,fgYellow,&"{peek}\n"
          
          var regionNode = %*{
            "region": %*{
              "start": &"0x{cast[uint64](mbi.BaseAddress):016X}",
              "size": &"0x{mbi.RegionSize:X}",
              "protect": mProtect,
              "state": mState,
              "type": mType,
              "entropy": entropy,
              "path": mappedPath,
              "peek": peek
            },
            "threads": newJArray(),
            "regex_matches": newJArray()
          }
          
          for ti in threadDetails:
            if ti.hasKey("start_address") and ti["start_address"].kind != JNull:
              let
                addrStr = ti["start_address"].getStr().replace("0x", "")
                threadAddr = parseHexStrToUInt64(addrStr)

              if threadAddr >= regionStart and threadAddr < regionEnd:
                regionNode["threads"].add(ti)
                fLog.log(lvlInfo, &"Thread start addr found in region: 0x{cast[uint](mbi.BaseAddress):016X}")

                let prio = ti["priority"]
                styledEcho styleBright,fgGreen,"[+] Thread found in region: ",resetStyle,fgWhite,&"0x{cast[uint](mbi.BaseAddress):016X}"
                styledEcho styleBright,fgWhite,"  | priority: ",resetStyle,fgMagenta,&"{prio}\n"

          #[ dumb way of checking for/getting wide strings ]#
          let sBuff = cast[string](buffer[0 ..< bytesRead])
          const wsrex = re2(r"(?:[\x20-\x7E]\x00){4,}", {regexArbitraryBytes})

          var 
            wideStrs = newSeq[string]()
            wideMap  = initTable[string, seq[int]]()

          for wsMatch in findAll(sBuff, wsrex):
            let 
              wsOffset = wsMatch.boundaries.a
              ws = stripNulls(sBuff[wsMatch.boundaries])
          
            if not wideMap.hasKey(ws):
              wideMap[ws] = @[]
            wideMap[ws].add(wsOffset)

          for (label, rex) in rexes:
            for strVal, offsets in wideMap:
              let cwMatch = find(strVal, rex)
              if cwMatch.isSome:
                for offset in offsets:
                  let 
                    peek = strVal[0 ..< min(strVal.len, 50)]
                    matchAddr = cast[uint64](mbi.BaseAddress) + offset.uint64
                  

                  let wMatchNode = %*{
                    "label": label,
                    "type": "wide",
                    "offset": &"0x{matchAddr:016X}",
                    "match": strVal
                  }
                  regionNode["regex_matches"].add(wMatchNode)

                  fLog.log(lvlInfo, &"[ {label} ] wide match found at: 0x{matchAddr:016X}")
                  styledEcho styleBright,fgGreen,&"[ {label} ] match at: ",resetStyle,fgWhite,&"0x{matchAddr:016X}"
                  styledEcho styleBright,fgWhite,"  | peek: ",resetStyle,fgMagenta,&"{peek}\n"

          for (label, rex) in rexes:
            for match in sBuff.findIter(rex):
              let 
                offset    = match.matchBounds.a 
                matchAddr = cast[uint64](mbi.BaseAddress) + offset.uint64
                peek = match.match[0 ..< min(match.match.len, 50)]
              
              let aMatchNode = %*{
                "label": label,
                "type": "ascii",
                "address": &"0x{matchAddr:016X}",
                "match": match.match
              }
              regionNode["regex_matches"].add(aMatchNode)

              fLog.log(lvlInfo, &"[ {label} ] ascii match found at: 0x{matchAddr:016X}")
              styledEcho styleBright,fgGreen,&"[ {label} ] match found at: ",resetStyle,fgWhite,&"0x{matchAddr:016X}"
              styledEcho styleBright,fgWhite,"  | peek: ",resetStyle,fgMagenta,&"{peek}\n"

          result.add(regionNode)
      else:
        let err = GetLastError()
        fLog.log(lvlError, &"Failed read at: 0x{cast[uint64](mbi.BaseAddress):016X} | err: {err}")
      currentAddr = cast[PVOID](cast[uint64](mbi.BaseAddress) + mbi.RegionSize.uint64)
    result
  
  else:
    fLog.log(lvlInfo, &"--------------- [ Start for PID: {pid} ] ----------------")
    if geteuid() != 0: 
      styledEcho styleBright,bgYellow,fgBlack,"[!] Not root"
      fLog.log(lvlWarn, "Not running under root")

    let mapsPath = "/proc/" & $pid & "/maps"
    let memPath  = "/proc/" & $pid & "/mem"

    if not fileExists(mapsPath) or not fileExists(memPath):
      styledEcho styleBlink,fgRed,bgBlue,"[X] Process memory not accessable"
      fLog.log(lvlError, &"unable to get /proc/{pid}/mem or /proc/{pid}/maps")
      quit(0)
    
    let threadInfo = getThreadDetails(pid)
    let memfile = open(memPath, fmRead)
    defer: memFile.close()

    for mLine in lines(mapsPath):
      let parts = mLine.splitWhitespace(maxSplit=5)
      if parts.len < 5 or 'r' notin parts[1]: 
        continue 

      let 
        protect    = parts[1]
        addrRange  = parts[0].split('-')
        startAddr  = parseHexInt(addrRange[0])
        endAddr    = parseHexInt(addrRange[1])
        regionSize = endAddr - startAddr
        mappedPath = if parts.len >= 6: parts[5] else: ""

      try:
        memFile.setFilePos(startAddr)
        var buffer    = newString(regionSize)
        let bytesRead = memFile.readBuffer(addr buffer[0], regionSize)
        if bytesRead == 0:
          continue

        let peek = toPrintable(buffer[0 ..< min(buffer.len, 120)])

        var entropy: float = 0.0
        if chkEntropy:
          entropy = getEntropy(buffer.toOpenArrayByte(0, bytesRead-1))
        if entropy >= threshold:
          fLog.log(lvlInfo, &"High entropy in region at: 0x{startAddr:016X}")
          styledEcho styleBright,fgGreen,&"[+] High entropy in region at: ",resetStyle,fgWhite,&"0x{startAddr:016X}"
          styledEcho styleBright,fgWhite,"  | protect: ",resetStyle,fgCyan,&"{protect}"
          styledEcho styleBright,fgWhite,"  | entropy: ",resetStyle,fgRed,&"{entropy:.2f}"
          styledEcho styleBright,fgWhite,"  | path: ",resetStyle,fgMagenta,&"{mappedPath}"
          styledEcho styleBright,fgWhite,"  | peek: ",resetStyle,fgYellow,&"{peek}\n"

        var regionNode = %*{
          "region": %*{
            "start": &"0x{startAddr:016X}",
            "size": &"0x{regionSize:X}",
            "protect": protect,
            "entropy": &"{entropy:.2f}",
            "path": mappedPath,
            "peek": peek
          },
          "threads": newJArray(),
          "regex_matches": newJArray()
        }

        for ti in threadInfo:
          let ip = parseHexInt(ti["registers"]["rip"].getStr().replace("0x", ""))
          if ip >= startAddr and ip < endAddr:
            regionNode["threads"].add(ti)
            let 
              ppid  = ti["ppid"]
              state = ti["state"]
              name  = ti["name"]
              prio  = ti["priority"]

            fLog.log(lvlInfo, &"Thread active in region: 0x{startAddr:016X}")
            styledEcho styleBright,fgGreen,"[+] Thread found in region: ",resetStyle,fgWhite,&"0x{startAddr:016X}"
            styledEcho styleBright,fgWhite,"  | ppid: ",resetStyle,fgCyan,&"{ppid}"
            styledEcho styleBright,fgWhite,"  | state: ",resetStyle,fgMagenta,&"{state}"
            styledEcho styleBright,fgWhite,"  | name: ",resetStyle,fgMagenta,&"{name}"
            styledEcho styleBright,fgWhite,"  | priority: ",resetStyle,fgRed,&"{prio}\n"

        for (label, rex) in rexes:
          for match in buffer.findIter(rex):
            let 
              offset    = match.matchBounds.a
              matchAddr = startAddr + offset 
              peek = match.match[0 ..< min(match.match.len, 50)]

            let matchNode = %*{
              "label": label,
              "match": match.match,
              "address": &"0x{matchAddr:016X}"
            }
            regionNode["regex_matches"].add(matchNode)

            fLog.log(lvlInfo, &"[ {label} ] match found at 0x{matchAddr:016X}")
            styledEcho styleBright,fgGreen,&"[ {label} ] match found at ",resetStyle,fgWhite,&"0x{matchAddr:016X}"
            styledEcho styleBright,fgWhite,"  | peek: ",resetStyle,fgMagenta,&"{peek}\n"

        result.add(regionNode)
      except IOError as err:
        fLog.log(lvlError, &"IOError at region start: 0x{startAddr:016X} -> {err.msg}")
      except Exception as err:
        fLog.log(lvlError, &"at region start: 0x{startAddr:016X} -> {err.msg}")
    result
    