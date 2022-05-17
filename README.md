## dreadful

An IDA Pro plugin to help in disassembly of Metroid Dread.

* `src/dreadful-ast-matcher`: Encapsulates parts of the code of the plugin that call into Clang.
* `src/dreadful-plugin-ida-base`: Encapsules parts of the code of the plugin that call into IDA's SDK.
* `src/dreadful-plugin-dump`: A simple plugin, unrelated to Metroid Dread, that dumps pseudocode consumable by Clang in IDA's output window.
* `src/dreadful-plugin`: The actual implementation of the plugin.

