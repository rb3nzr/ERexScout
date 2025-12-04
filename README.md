# About
CLI tool to scan process memory and files.

Finds matches based on a given regular expression or set of them (add those to core/rexes.nim).
Finds high entropy regions based on the set threshold.
Produces extra information (per region, file, etc.) and exports as JSON.

Built as a learning excersise. The regex matching needs work.

# Compile & Usage
nimble install cligen regex winim ptrace
nim c -d:release erex_scout.nim

```text
Options:
  -h, --help                          print this cligen-erated help
  --help-syntax                       advanced: prepend,plurals,..
  -p=, --pid=          int     0      Process to scan
  -d=, --path=         string  ""     Directory path for file scanning
  -r, --recurse        bool    false  Recursively process files from the given directory path
  -e, --entropy        bool    false  Check entropy
  -t=, --threshold=    float   6.7    Entropy threshold
  -c=, --chunk-size=   int     120    Size of chunks for entropy checks (files only)
  -l, --list-groups    bool    false  List the available regex groups
  -g=, --rex-group=    string  ""     Pass the regex group to use
  -u=, --user-rex=     string  ""     Provide a single regex to use
  -o=, --output-path=  string  ""     JSON output file path (appends)
```

# Example Output
*Files:*
```json
{
  "RootDir-/home/rb3nzr/Desktop/DRIVE/test": [
    {
      "file_name": "/home/rb3nzr/Desktop/DRIVE/test/unk.vbe",
      "signature_match": "Unknown",
      "file_size": "1405.50 KB",
      "link_count": 1,
      "is_hidden": false,
      "last_access": "2025-12-04 10:46:32",
      "last_write": "2025-12-04 10:31:32",
      "created": "2025-12-04 10:46:54",
      "permissions": "{fpUserWrite, fpUserRead, fpGroupRead, fpOthersRead}",
      "file_entropy": "0.00",
      "file_hash": "F0EB038E5B5024CA2F59CB6A3F09D56396CBCCF4",
      "peek": "Option Explicit....'==============================================================================..' Main Controller Cl",
      "high_entropy_sections": [],
      "regex_matches": [
        {
          "label": "base64_2",
          "type": "ascii",
          "offset": "0x00001FE5",
          "match": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        },
        {
          "label": "base64_2",
          "type": "ascii",
          "offset": "0x00002996",
          "match": "DQojIEVuY3J5cHRlZCBQb ..[SNIP].. ml0ZS1Ib3N0ICRlcnJvck1lc3NhZ2VzWzBdDQp9DQo="
        },
        {
          "label": "file_path",
          "type": "ascii",
          "offset": "0x0000027B",
          "match": "C:\\Temp"
        }
      ]
    }
  ]
}
```
*Memory:*
```json
{
  "Process-3288": [
    {
      "region": {
        "start": "0x00007FF6AF751000",
        "size": "0x4E000",
        "protect": "EXECUTE_READ",
        "state": "COMMIT",
        "type": "IMAGE",
        "entropy": 5.600674091882972,
        "path": "\\Device\\HarddiskVolume4\\Users\\rb3nzr\\Desktop\\Sideloading\\SL-OST-Exp\\src\\loader_t2.exe",
        "peek": "UH..H.M.H.U.L.E D.M(.].UH..H.. .\\.........H..OS......t.........................&..H...R........&..H...R...........H..7Q."
      },
      "threads": [
        {
          "tid": 1168,
          "start_address": "0x00007FF6AF751125",
          "user_time": 1.15625,
          "kernel_time": 0.0,
          "creation_time": 13409340728.448286,
          "priority": "NORMAL",
          "context": {
            "dr0": "0x00007FFD40C117F0",
            "dr1": "0x0000000000000000",
            "dr2": "0x0000000000000000",
            "dr3": "0x0000000000000000",
            "dr7": "0x0000000000000401",
            "flags": "0x00000246"
          },
          "seh_info": {
            "is_corrupted": false,
            "chain_length": 0,
            "chain": []
          }
        }
      ],
      "regex_matches": []
    }
  ]
}
```
```json
{
  "Process-11612": [
    {
      "region": {
        "start": "0x00000000001A0000",
        "size": "0x4000",
        "protect": "READONLY",
        "state": "COMMIT",
        "type": "MAPPED",
        "entropy": 3.1542398485543135,
        "path": "",
        "peek": "Actx .......,3.......... ...................4...|...............................N.&.....D.......T........q2.4...J......."
      },
      "threads": [],
      "regex_matches": [
        {
          "label": "path",
          "type": "wide",
          "offset": "0x00000000001A1A8C",
          "match": "C:\\Windows\\SysWOW64\\GdiPlus.dll"
        }
      ]
    },
    {
      "region": {
        "start": "0x0000000000401000",
        "size": "0x7000",
        "protect": "EXECUTE_READ",
        "state": "COMMIT",
        "type": "IMAGE",
        "entropy": 6.248416131100585,
        "path": "\\Device\\HarddiskVolume4\\Users\\rb3nzr\\Desktop\\997fd3d11c6decadf7a56e384228fda1a8224bd4ed00e1c7767b998cc08e2196.exe",
        "peek": "U....\\.}..t+.}.F.E.u..H.....OC..H.P.u..u..u.....@..B...SV.5.OC..E.WP.u.....@..e...E..E.P.u.....@..}..e....`.@........FR."
      },
      "threads": [
        {
          "tid": 11620,
          "start_address": "0x000000000040352D",
          "user_time": 1.890625,
          "kernel_time": 3.890625,
          "creation_time": 1844674407199.963,
          "priority": "NORMAL",
          "context": {
            "dr0": "0x0000000000000000",
            "dr1": "0x0000000000000000",
            "dr2": "0x0000000000000000",
            "dr3": "0x0000000000000000",
            "dr7": "0x0000000000000000",
            "flags": "0x00000206"
          },
          "seh_info": {
            "is_corrupted": false,
            "chain_length": 2,
            "chain": [
              {
                "address": "0x00000000003D1000",
                "handler": "0x00000000001A0000",
                "handler_module": "",
                "next": "0x000000000019F138"
              },
              {
                "address": "0x000000000019F138",
                "handler": "0x0000000075ECC740",
                "handler_module": "\\Device\\HarddiskVolume4\\Windows\\SysWOW64\\user32.dll",
                "next": "0x0000000000000000"
              }
            ]
          }
        },
        {
          "tid": 11452,
          "start_address": "0x0000000000405672",
          "user_time": 0.890625,
          "kernel_time": 1.671875,
          "creation_time": 1844674407200.071,
          "priority": "NORMAL",
          "context": {
            "dr0": "0x0000000000000000",
            "dr1": "0x0000000000000000",
            "dr2": "0x0000000000000000",
            "dr3": "0x0000000000000000",
            "dr7": "0x0000000000000000",
            "flags": "0x00000246"
          },
          "seh_info": {
            "is_corrupted": false,
            "chain_length": 3,
            "chain": [
              {
                "address": "0x00000000003E5000",
                "handler": "0x0000000005090000",
                "handler_module": "",
                "next": "0x000000000508FFCC"
              },
              {
                "address": "0x000000000508FFCC",
                "handler": "0x0000000076F81C70",
                "handler_module": "\\Device\\HarddiskVolume4\\Windows\\SysWOW64\\ntdll.dll",
                "next": "0x000000000508FFE4"
              },
              {
                "address": "0x000000000508FFE4",
                "handler": "0x0000000076FB46A2",
                "handler_module": "\\Device\\HarddiskVolume4\\Windows\\SysWOW64\\ntdll.dll",
                "next": "0x00000000FFFFFFFF"
              }
            ]
          }
        }
      ],
      "regex_matches": []
    }
  ]
}
```
