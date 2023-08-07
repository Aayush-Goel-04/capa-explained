# CAPA-doc 
## How CAPA Works
CAPA is an open-source tool developed by the FLARE team to identify capabilities in executable files. Here's the github repo link for capa https://github.com/mandiant/capa.

### Usage:

### Positional Arguments:
- `sample`: Path to the sample file you want to analyze.

### Optional Arguments:
- `-h, --help`: Show this help message and exit.
- `--version`: Show the program's version number and exit.
- `-v, --verbose`: Enable verbose result document (no effect with --json).
- `-vv, --vverbose`: Enable very verbose result document (no effect with --json).
- `-d, --debug`: Enable debugging output on STDERR.
- `-q, --quiet`: Disable all output but errors.
- `--color {auto,always,never}`: Enable ANSI color codes in results. Default: enabled only during an interactive session.
- `-f {auto,pe,dotnet,elf,sc32,sc64,freeze}, --format {auto,pe,dotnet,elf,sc32,sc64,freeze}`: Select the sample format. Default: auto, which detects the file type automatically. Other options include pe (Windows PE file), dotnet (.NET PE file), elf (Executable and Linkable Format), sc32 (32-bit shellcode), sc64 (64-bit shellcode), and freeze (features previously frozen by capa).
- `-b {vivisect,binja,pefile}, --backend {vivisect,binja,pefile}`: Select the backend to use for feature extraction. Options include vivisect (default), binja, and pefile.
- `--os {auto,linux,macos,windows}`: Select the sample's operating system. Default: auto, which detects the OS automatically. Other options include linux, macos, and windows.
- `-r RULES, --rules RULES`: Path to a rule file or directory. If not specified, CAPA uses the default embedded rules.
- `-s SIGNATURES, --signatures SIGNATURES`: Path to a .sig/.pat file or directory used to identify library functions. If not specified, CAPA uses the default embedded signatures.
- `-t TAG, --tag TAG`: Filter on rule meta field values.
- `-j, --json`: Emit JSON instead of text.

## Specifying the File Format
If the format is not specified, CAPA automatically determines the file format by reading the starting bytes of the sample file.

## Loading Rules
CAPA creates a `RuleSet: List[Rule]` from the default rule paths if none are specified. To learn more about rules, visit the [CAPA Rules Format Documentation](https://github.com/mandiant/capa-rules/blob/master/doc/format.md).

## Extracting File Metadata and Capabilities
To extract file metadata and capabilities, follow these steps:

1. Create an appropriate feature extractor, such as Vivisect, Binary Ninja, or other compatible workspaces, and use it for extracting capabilities.
2. For PE format files, CAPA retrieves signatures from signature files (FLIRT Signatures). These signatures enable library code matching through symbol matching. For example, a FLIRT signature for `strcmp` might look like this: `55 8B EC 83 EC 0C 8B 45 08 8B 4D 0C 8B 55 10 83 F9 00 75 17 0F B6 01 3A 45 0C 74 0A 3A 01 75 05 83 C0 01 5D C3`.
3. CAPA creates a feature extractor based on the file format. The default debugger framework used for extraction is [Vivisect](https://github.com/vivisect/vivisect), but CAPA is also compatible with IDAPro for feature extraction. The [viv-utils](https://github.com/williballenthin/viv-utils) module provides functionalities to retrieve function handles from sample binary files.
4. Basic file information, such as file hashes, operating system, format, architecture, and the path of rules used for analysis, is loaded into a Meta Data Type.
5. CAPA finds capabilities by taking a ruleset and a feature extractor as input and returns a tuple of (matches, meta). It first identifies all capabilities within functions, basic blocks, and instructions. Then, it collects all rule matches across all scopes and identifies all capabilities in the files. Finally, it returns the matches and metadata.

## Result
Analysis done in above steps is then rendered to user. example :

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

# Further Information
for further information visit CAPA's official repo https://github.com/mandiant/capa
