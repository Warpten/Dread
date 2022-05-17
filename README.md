## dreadful

An IDA Pro plugin to help in disassembly of Metroid Dread.

* `src/dreadful-ast-matcher`: Encapsulates parts of the code of the plugin that call into Clang.
* `src/dreadful-plugin-ida-base`: Encapsules parts of the code of the plugin that call into IDA's SDK.
* `src/dreadful-plugin-dump`: A simple plugin, unrelated to Metroid Dread, that dumps pseudocode consumable by Clang in IDA's output window.
* `src/dreadful-plugin`: The actual implementation of the plugin.

### Supported versions

|  | MD5 | State |
|---|---|---|
| V1.0 | F5D9AA2AF3ABEF3070791057060EE93C | WIP |

## Algorithm

We search for each call site of `CRC64` (a function we look for on each version of the binary), and disassemble all callers. We then look for patterns such as:
```
*(a1 + N) = ...; // and/or with casts
*(&a1 + N) = ...; // and/or with casts
```
![Sample disassembly of a relevant function](https://i.imgur.com/jvaZgyA.png)

From this, we can deduce properties about each type, including :
* their constructors (parameterless, copy, move) and destructors
* type hierarchy
* properties if the type is a structure
* enumeration values if the type is a value.
