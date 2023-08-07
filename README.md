# CAPA-doc
## How capa works
```
The FLARE team's open-source tool to identify capabilities in executable files.

positional arguments:
  sample                path to sample to analyze

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         enable verbose result document (no effect with --json)
  -vv, --vverbose       enable very verbose result document (no effect with --json)
  -d, --debug           enable debugging output on STDERR
  -q, --quiet           disable all output but errors
  --color {auto,always,never}
                        enable ANSI color codes in results, default: only during interactive session
  -f {auto,pe,dotnet,elf,sc32,sc64,freeze}, --format {auto,pe,dotnet,elf,sc32,sc64,freeze}
                        select sample format, auto: (default) detect file type automatically, pe: Windows PE file, dotnet: .NET PE file, elf: Executable and Linkable Format, sc32:
                        32-bit shellcode, sc64: 64-bit shellcode, freeze: features previously frozen by capa
  -b {vivisect,binja,pefile}, --backend {vivisect,binja,pefile}
                        select the backend to use
  --os {auto,linux,macos,windows}
                        select sample OS: auto (detect OS automatically - default), linux, macos, windows
  -r RULES, --rules RULES
                        path to rule file or directory, use embedded rules by default
  -s SIGNATURES, --signatures SIGNATURES
                        path to .sig/.pat file or directory used to identify library functions, use embedded signatures by default
  -t TAG, --tag TAG     filter on rule meta field values
  -j, --json            emit JSON instead of text
```

## Specifiying file format
If format is not specified the file format is found by reading the starting bytes of sample file.

## Loading Rules
A `RuleSet: List[Rule]` is created from the default rules paths if not specified. [What are Rules.](https://github.com/mandiant/capa-rules/blob/master/doc/format.md)

## Extracting file metadata and capabilities
We must create an extractor and use that to extract meta and capabilities, we must create an extractor, such as viv, binary ninja, etc. workspaces and use those for extracting.

-  Loading FLIRT Signatures : If file is PE format get signatures from signature files. This helps us do library code matching by having symbol matching.
Exampe FLIRT signature for `strcmp`: `55 8B EC 83 EC 0C 8B 45 08 8B 4D 0C 8B 55 10 83 F9 00 75 17 0F B6 01 3A 45 0C 74 0A 3A 01 75 05 83 C0 01 5D C3`
- Get Extractor : A feature extractor is created based on file format. [vivisect](https://github.com/vivisect/vivisect) is the default debugger framework used for extracting file capabilities. capa is also compatible with IDAPro for feature extraction. [viv-utils](https://github.com/williballenthin/viv-utils) is a utilities module for working with vivisect. It provides us with functionalities of vivisect to get function handles from sample binary file.
- Collect MetaData : Basic file info (like file hashes, os, format, arch and path of rules to be used for analysis) is loaded into a Meta Data Type.
- Finding Capabilities : It takes a ruleset and a feature_extractor, and returns a tuple of (matches, meta), where: it first finds all capabilities within functions, basic blocks, and instructions. It then collects all rule matches across all scopes, and finds all capabilities in files. Finally, it returns the matches and metadata.

## Results
The capabilities found using extractor are rendered and displayed to user.
```
$ capa.exe suspicious.exe

+------------------------+--------------------------------------------------------------------------------+
| ATT&CK Tactic          | ATT&CK Technique                                                               |
|------------------------+--------------------------------------------------------------------------------|
| DEFENSE EVASION        | Obfuscated Files or Information [T1027]                                        |
| DISCOVERY              | Query Registry [T1012]                                                         |
|                        | System Information Discovery [T1082]                                           |
| EXECUTION              | Command and Scripting Interpreter::Windows Command Shell [T1059.003]           |
|                        | Shared Modules [T1129]                                                         |
| EXFILTRATION           | Exfiltration Over C2 Channel [T1041]                                           |
| PERSISTENCE            | Create or Modify System Process::Windows Service [T1543.003]                   |
+------------------------+--------------------------------------------------------------------------------+

+-------------------------------------------------------+-------------------------------------------------+
| CAPABILITY                                            | NAMESPACE                                       |
|-------------------------------------------------------+-------------------------------------------------|
| check for OutputDebugString error                     | anti-analysis/anti-debugging/debugger-detection |
| read and send data from client to server              | c2/file-transfer                                |
| execute shell command and capture output              | c2/shell                                        |
| receive data (2 matches)                              | communication                                   |
| send data (6 matches)                                 | communication                                   |
| connect to HTTP server (3 matches)                    | communication/http/client                       |
| send HTTP request (3 matches)                         | communication/http/client                       |
| create pipe                                           | communication/named-pipe/create                 |
| get socket status (2 matches)                         | communication/socket                            |
| receive data on socket (2 matches)                    | communication/socket/receive                    |
| send data on socket (3 matches)                       | communication/socket/send                       |
| connect TCP socket                                    | communication/socket/tcp                        |
| encode data using Base64                              | data-manipulation/encoding/base64               |
| encode data using XOR (6 matches)                     | data-manipulation/encoding/xor                  |
| run as a service                                      | executable/pe                                   |
| get common file path (3 matches)                      | host-interaction/file-system                    |
| read file                                             | host-interaction/file-system/read               |
| write file (2 matches)                                | host-interaction/file-system/write              |
| print debug messages (2 matches)                      | host-interaction/log/debug/write-event          |
| resolve DNS                                           | host-interaction/network/dns/resolve            |
| get hostname                                          | host-interaction/os/hostname                    |
| create a process with modified I/O handles and window | host-interaction/process/create                 |
| create process                                        | host-interaction/process/create                 |
| create registry key                                   | host-interaction/registry/create                |
| create service                                        | host-interaction/service/create                 |
| create thread                                         | host-interaction/thread/create                  |
| persist via Windows service                           | persistence/service                             |
+-------------------------------------------------------+-------------------------------------------------+
```
