---
layout: post
title:  "Building libFuzzer fuzzers on Windows with cmake/Visual Studio"
date:   2019-08-07 00:00:00 -0400
categories: fuzzing
---

libFuzzer is awesome and is currently my go-to fuzzing tool, so I was super excited last week when I learned that both 
[libFuzzer](https://llvm.org/docs/LibFuzzer.html) and [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) 
are now supported on Windows! I put together a couple notes on how I got it to work with a cmake + Visual Studio project.

I will use [libwasm-vulnerable](https://github.com/ekse/libwasm-vulnerable/) as an example, this project is already set 
up to build a fuzzer.

## Configuration steps

The first step is to install a snapshot of clang 9 which can be downloaded from [https://llvm.org/builds/](https://llvm.org/builds/).

We also need to install the clang support for Visual Studio. In Visual Studio Installer, it can be found under
"Individual Components" as "C++ Clang-cl for v142 build tools".

## Project generation

The next step is to generate the cmake build using the `ClangCl` toolset. Here `WASM_FUZZING` is a flag specific to
`libwasm-vulnerable` that is used to build the fuzzers (see the project
[CMakeLists.txt](https://github.com/ekse/libwasm-vulnerable/blob/master/CMakeLists.txt#L18) for details).

```
cmake -G "Visual Studio 16" -T ClangCl -DWASM_FUZZING=ON ../..
```

Next, open the `libwasm.sln` project in Visual Studio. A limitation of libFuzzer on Windows is that incremental builds
are not supported. To avoid this issue, I build the project in "Release" mode.

Another limitation of libFuzzer on Windows is that it only supports the /MT runtime library (it will fail to compile
with /MD or /MTd). We need to change it for both libwasm and FuzzLibwasm. To do that, right-click on the project,
select "Properties", then under "Configuration properties" / "C/C++" / "Code generation", set "Runtime library" to
"Multithread /MT".

The last thing we need to fix is adding the libFuzzer libraries as they are not automatically added. To do that, open
the Properties page of FuzzLibwasm, go to "Linking" / "Entries" and open "Additional Dependencies". Add the following
lines (the paths might be different on your system).

```
C:\Program Files\LLVM\lib\clang\9.0.0\lib\windows\clang_rt.asan-preinit-x86_64.lib
C:\Program Files\LLVM\lib\clang\9.0.0\lib\windows\clang_rt.asan-x86_64.lib
C:\Program Files\LLVM\lib\clang\9.0.0\lib\windows\clang_rt.asan_cxx-x86_64.lib
C:\Program Files\LLVM\lib\clang\9.0.0\lib\windows\clang_rt.fuzzer-x86_64.lib
```

FuzzLibwasm should now build and run normally (and should find a crash almost right away).

```
C:\projects\Security\libwasm-vulnerable\builds\Fuzzing2>fuzzers\Release\FuzzLibwasm.exe
INFO: Seed: 3746082236
INFO: Loaded 1 modules   (331 inline 8-bit counters): 331 [00007FF72401B908, 00007FF72401BA53),
INFO: Loaded 1 PC tables (331 PCs): 331 [00007FF723FF3EA8,00007FF723FF5358),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 6 ft: 6 corp: 1/1b exec/s: 0 rss: 62Mb
=================================================================
==20928==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x11e35af80893 at pc 0x7ff723e68a02 bp 0x001618efee90 sp 0x001618efeed8
READ of size 1 at 0x11e35af80893 thread T0
    #0 0x7ff723e68a01 in WasmDisasm_NextInstruction+0x6d1 (C:\projects\Security\libwasm-vulnerable\builds\Fuzzing2\fuzzers\Release\FuzzLibwasm.exe+0x140008a01)
    #1 0x7ff723e61115 in LLVMFuzzerTestOneInput+0x65 (C:\projects\Security\libwasm-vulnerable\builds\Fuzzing2\fuzzers\Release\FuzzLibwasm.exe+0x140001115)
    #2 0x7ff723eb0edd in fuzzer::Fuzzer::ExecuteCallback C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:553
    #3 0x7ff723eb0296 in fuzzer::Fuzzer::RunOne C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:469
    #4 0x7ff723eb2030 in fuzzer::Fuzzer::MutateAndTestOne C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:695
    #5 0x7ff723eb2df5 in fuzzer::Fuzzer::Loop C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:831
    #6 0x7ff723ea725f in fuzzer::FuzzerDriver C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\fuzzer\FuzzerDriver.cpp:825
    #7 0x7ff723ef11d2 in main C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\fuzzer\FuzzerMain.cpp:19
    #8 0x7ff723f49b5b in __scrt_common_main_seh d:\agent\_work\3\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:288
    #9 0x7ffa07227973 in BaseThreadInitThunk+0x13 (C:\WINDOWS\System32\KERNEL32.dll+0x180017973)
    #10 0x7ffa0913a270 in RtlUserThreadStart+0x20 (C:\WINDOWS\SYSTEM32\ntdll.dll+0x18006a270)

0x11e35af80893 is located 0 bytes to the right of 3-byte region [0x11e35af80890,0x11e35af80893)
allocated by thread T0 here:
    #0 0x7ff723e96924 in operator new[] C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\asan\asan_new_delete.cc:102
    #1 0x7ff723eb0df1 in fuzzer::Fuzzer::ExecuteCallback C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:538
    #2 0x7ff723eb0296 in fuzzer::Fuzzer::RunOne C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:469
    #3 0x7ff723eb2030 in fuzzer::Fuzzer::MutateAndTestOne C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:695
    #4 0x7ff723eb2df5 in fuzzer::Fuzzer::Loop C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\fuzzer\FuzzerLoop.cpp:831
    #5 0x7ff723ea725f in fuzzer::FuzzerDriver C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\fuzzer\FuzzerDriver.cpp:825
    #6 0x7ff723ef11d2 in main C:\src\llvm_package_363781\llvm\projects\compiler-rt\lib\fuzzer\FuzzerMain.cpp:19
    #7 0x7ff723f49b5b in __scrt_common_main_seh d:\agent\_work\3\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl:288
    #8 0x7ffa07227973 in BaseThreadInitThunk+0x13 (C:\WINDOWS\System32\KERNEL32.dll+0x180017973)
    #9 0x7ffa0913a270 in RtlUserThreadStart+0x20 (C:\WINDOWS\SYSTEM32\ntdll.dll+0x18006a270)

SUMMARY: AddressSanitizer: heap-buffer-overflow (C:\projects\Security\libwasm-vulnerable\builds\Fuzzing2\fuzzers\Release\FuzzLibwasm.exe+0x140008a01) in WasmDisasm_NextInstruction+0x6d1
Shadow bytes around the buggy address:
  0x041bc65700c0: fa fa 05 fa fa fa fd fa fa fa 06 fa fa fa 00 00
  0x041bc65700d0: fa fa 00 00 fa fa 00 fa fa fa 00 fa fa fa 00 fa
  0x041bc65700e0: fa fa 00 00 fa fa 00 fa fa fa 00 fa fa fa fd fd
  0x041bc65700f0: fa fa fd fd fa fa fd fd fa fa fd fa fa fa fd fa
  0x041bc6570100: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
=>0x041bc6570110: fa fa[03]fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x041bc6570120: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x041bc6570130: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x041bc6570140: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x041bc6570150: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x041bc6570160: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==20928==ABORTING
MS: 2 InsertByte-InsertByte-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
0x11,0xa,0x2d,
\x11\x0a-
artifact_prefix='./'; Test unit written to ./crash-dac57cac066b9b5ec2f3f5f64595a40609d52e80
Base64: EQot
```