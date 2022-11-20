# EDI-CLI

CLI tool for working with EDI files.

This crate is still a work in progress.

Edifact implementation is based on the `edifact-types` crate.
X12 implementation is based ont the `x12-types` crate.

# Install

We currently only support install through cargo

```
cargo install edi-cli
```

# Usage

```
% ./edi 
Edi file processing

Usage: edi <COMMAND>

Commands:
  edi2json  Transforms an EDI into a Json document
  json2edi  Transforms an Json into a EDI document
  encoding  returns either 'X12' or 'EDIFACT' if encoding can be determined, otherwise 'UNKNOWN'.
  type      returns the X12 or EDIFACT message type
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help information
  -V, --version  Print version information
```

## get encoding
```
% ./edi encoding 004010_315.edi 
X12
```

## get type
```
% ./edi type 004010_315.edi 
004010/315
```

## edi2json
```
% ./edi edi2json 004010_315.edi 
{"isa":{"01":"00","02":"          ","03":"00","04":"          ","05":"ZZ","06":"SOURCE         ","07":"ZZ","08":"TARGET         ","09":"220524","10":"1120","11":"U","12":"00401","13":"000000001","14":"0","15":"P","16":">"},"functional_group":[{"gs":{"01":"QO","02":"SOURCE","03":"TARGET","04":"20220524","05":"1600","06":"1","07":"X","08":"004010"},"segments":[{"st":{"01":"315","02":"00001"},"b4":{"03":"VA","04":"20220901","05":"0807","07":"GMCU","08":"609413","09":"E","11":"LOCKBOURNE","12":"CI","13":"7"},"n9":[{"01":"BM","02":"21001ASK5V9U"},{"01":"BN","02":"1NAN910141"},{"01":"EQ","02":"GMCU6094137"}],"q2":{"01":"9330141","09":"202N","12":"L","13":"MARIM"},"loop_r4":[{"r4":{"01":"L","02":"UN","03":"USMEM","04":"BNSF MEMPHIS RAMP","05":"US","08":"US"}},{"r4":{"01":"E","02":"UN","03":"USDAL","04":"BNSF ALLIANCE RAMP","05":"US","08":"US"}}],"se":{"01":"9","02":"00001"}}],"ge":{"01":"1","02":"1"}}],"iea":{"01":"1","02":"000000001"}}
```