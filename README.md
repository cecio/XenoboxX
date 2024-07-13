# XenoboxX

Hardware Sandbox Toolkit

------

Malware frequently employs anti-VM techniques, which can vary in their  difficulty to detect and counteract. While integrating anti-detection  measures in our labs is a frequently used option, we should also  consider using a real hardware sandbox, even if this sounds weird. By leveraging the awesome [PCILeech](https://github.com/ufrisk/pcileech) project and DMA hardware access,  **XenoboxX** provides a suite of tools for analysis tasks, such as dumping  dynamically allocated memory and searching for IoC. These tools allow us to inject code at kernel level through DMA, making detection  significantly more challenging and giving a new perspective to the  analysis.

**XenoboxX** is currently focused on 64 bits Windows, but in the future it could be extended for other platforms too.

## What you need

Obviously we are speaking about physical environments, so:

- *target* **PC** with PCI interface. Since you are going to deploy *malware* on it, you probably want a test system with the possibility to roll back to a clean state. You can use your preferred way: kiosk softwares, rollback utilities or going with an imaging system with cloning software (or even hardware).
- **DMA  Board** compatible with **PCILeech** (see [home page](https://github.com/ufrisk/pcileech))
- [PCILeech](https://github.com/ufrisk/pcileech) installed on a *host* **PC** with an access to the **DMA Board** (usually USB connection)

## Quick Setup

- install the **DMA Board** on the *target* **PC**. Connect the board to your *host* **PC**

- install **PCILeech** on your *host* **PC**: if you are not going to develop or make modification, you can just install the binaries (I think this is the most common options) available in the [release page](https://github.com/ufrisk/pcileech/releases)

- install **XenoboxX** on your *host* **PC**: as for previous point, you may want just the pre-compiled binaries (in `pcileech` folder)

- inject **PCILeech** module:

  ```
  ./pcileech kmdload -kmd WIN10_X64_3
  ```

  this will return a memory address you'll use to run the shellcodes (ex `0x7ffff000`)

- run the **XenoboxX** shellcodes:

  ```
  ./pcileech wx64_dumpalloc -0 0xbac -s "\\??\C:\temp\test" -kmd 0x7ffff000
  ```

## More info

Currently **XenoboxX** has 3 wx64 shellcodes:

- `wx64_dumpalloc`: attach to a specific PID and dumps all memory allocations done by the process. If the protection flags of an existing memory are is changed, the region is dumped again (sometimes malware switches protections to avoid inspections)
- `wx64_memgrep`: search for user defined strings in the memory allocated by a PID. It can be attached for a specific amount of time to the process.
- `wx64_strings`: search for all strings in the memory allocated by a PID. It can be attached for a specific amount of time to the process.

**Note**: as an experimental approach, **Xenobox** currently avoid hooking at all, and all the detections are done through polling. Obviously this has some drawbacks, but this is a design choice at the moment, in order to be as stealthy as possible.

### wx64_dumpalloc

Example:

```
./pcileech wx64_dumpalloc -0 0xbac -s "\\??\C:\temp\test" -kmd 0x7ffff000
```

#### Options

- `-0` PID to attach to in hex format (required)
- `-1` process monitoring time. Default set to 0x20
- `-s` output folder, where memory dumps and log will be saved 

### wx64_memgrep

Example:

```
./pcileech wx64_memgrep -0 0x564 -1 0x80 -s "Hello, 123" -2 1 -kmd 0x7ffff000
```

#### Options

- `-0` PID to attach to in hex format (required)
- `-1` process monitoring time. Default set to 0x20
- `-2` search for ASCII (0x0) or WIDE (0x1) string. Default set to 0x0
- `-3` case sensitive (0x1) or insensitive (0x0) search. Case sensitive is faster. Default set to 0x0
- `-4` search only Writable memory pages (0x0) or all (0x01). Default set to 0x0
- `-s` search string (in double quotes)

### wx64_strings

Example:

```
./pcileech wx64_strings -0 0x19e0 -1 0x100 -3 0x15 -kmd 0x7ffff000
```

#### Options

- `-0` PID to attach to in hex format (required)
- `-1` process monitoring time. Default set to 0x20
- `-2` search for ASCII (0x0) or WIDE (0x1) string. Default set to 0x0
- `-3` string minimum length. Default set to 0xA
- `-4` search only Writable memory pages (0x0) or all (0x01). Default set to 0x0

## Final Notes

**XenoboxX** is not the definitive analysis tool: this is a very specific approach I find useful for very specific analysis: I don't think this tool is going to replace your current workflow, but may be you'll find it useful for that specific *nasty* malware.

## Contribute

Contributions and suggestions are more than welcome. Please open an issue if you have questions or a pull if you want to contribute. Thanks!
