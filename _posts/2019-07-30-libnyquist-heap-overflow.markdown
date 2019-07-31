---
layout: post
title:  "libnyquist: heap overflow in Vorbis decoder"
date:   2019-07-30 00:00:00 -0400
categories: fuzzing
---

## Summary

[libnyquist](https://github.com/ddiakopoulos/libnyquist) is a cross platform C++11 library for decoding audio (mp3, wav, ogg, opus, flac, etc). A heap overflow can happen in VorbisDecoderInternal::readInternal when the library attempts to read more frames than the allocated capacity of `AudioData->samples`.

crash input: [crash-7f190cd04b5fbf6f813db4447b5010e63867fe6a.ogg](https://drive.google.com/open?id=10xpTDUrHzJLFknsY4bF8333YpvnMHZJc)

For reference, the fuzzer can be found on my [fuzzing](https://github.com/ekse/libnyquist/tree/fuzzing) branch. The provided sample also crashes the sample `libnyquist-examples` that is provided with libnyquist.

## Detailed analysis

libnyquist can write past the capacity of `samples` in AudioData. With the provided crash sample, this happens when `totalFramesRead` reaches the value 19840.

`VorbisDecoderInternal::readInternal` contains the following code. The write overflow happens in `d->samples[totalFramesRead] = buffer[ch][i]`.

```c
for (int i = 0; i < framesRead; ++i)
{
    for(int ch = 0; ch < d->channelCount; ch++)
    {
        d->samples[totalFramesRead] = buffer[ch][i];
        totalFramesRead++;
    }
}
```

The size of samples is set in VorbisDecoderInternal::loadAudioData.

```c
auto totalSamples = size_t(getTotalSamples());

d->samples.resize(totalSamples * d->channelCount);
```

`getTotalSamples` is defined as follows.

```c
inline int64_t getTotalSamples() const { return int64_t(ov_pcm_total(const_cast<OggVorbis_File *>(fileHandle), -1)); }
```
In the crash sample, `totalSamples` is 9920, d->channelCount is 2, so samples is set to size 19840.

AddressSanitizer report:
```
==12481==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x631000027e00 at pc 0x000000822064 bp 0x7ffcb604acd0 sp 0x7ffcb604acc8
WRITE of size 4 at 0x631000027e00 thread T0
    #0 0x822063 in VorbisDecoderInternal::readInternal(unsigned long, unsigned long) /home/ekse/git/libnyquist/builds/Fuzzing/../../src/VorbisDecoder.cpp:105:49
    #1 0x820788 in VorbisDecoderInternal::loadAudioData(void*, ov_callbacks) /home/ekse/git/libnyquist/builds/Fuzzing/../../src/VorbisDecoder.cpp:248:14
    #2 0x81ef9a in VorbisDecoderInternal::VorbisDecoderInternal(nqr::AudioData*, std::vector<unsigned char, std::allocator<unsigned char> > const&) /home/ekse/git/libnyquist/builds/Fuzzing/../../src/VorbisDecoder.cpp:56:13
    #3 0x81ea87 in nqr::VorbisDecoder::LoadFromBuffer(nqr::AudioData*, std::vector<unsigned char, std::allocator<unsigned char> > const&) /home/ekse/git/libnyquist/builds/Fuzzing/../../src/VorbisDecoder.cpp:264:27
    #4 0x5347bc in nqr::NyquistIO::Load(nqr::AudioData*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, std::vector<unsigned char, std::allocator<unsigned char> > const&) /home/ekse/git/libnyquist/builds/Fuzzing/../../src/Common.cpp:133:22
    #5 0x52a6b3 in Fuzz_Decoder(unsigned char const*, unsigned long) /home/ekse/git/libnyquist/builds/Fuzzing/../../fuzzers/FuzzNyquist.cpp:20:12
    #6 0x52ad5b in LLVMFuzzerTestOneInput /home/ekse/git/libnyquist/builds/Fuzzing/../../fuzzers/FuzzNyquist.cpp:28:5
    #7 0x43231a in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/ekse/git/libnyquist/builds/Fuzzing/fuzzers/FuzzNyquist+0x43231a)
    #8 0x424c5c in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/home/ekse/git/libnyquist/builds/Fuzzing/fuzzers/FuzzNyquist+0x424c5c)
    #9 0x42a0e1 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/ekse/git/libnyquist/builds/Fuzzing/fuzzers/FuzzNyquist+0x42a0e1)
    #10 0x44c702 in main (/home/ekse/git/libnyquist/builds/Fuzzing/fuzzers/FuzzNyquist+0x44c702)
    #11 0x7fadf79f1b6a in __libc_start_main /build/glibc-KRRWSm/glibc-2.29/csu/../csu/libc-start.c:308:16
    #12 0x423539 in _start (/home/ekse/git/libnyquist/builds/Fuzzing/fuzzers/FuzzNyquist+0x423539)

0x631000027e00 is located 0 bytes to the right of 79360-byte region [0x631000014800,0x631000027e00)
allocated by thread T0 here:
    #0 0x527512 in operator new(unsigned long) (/home/ekse/git/libnyquist/builds/Fuzzing/fuzzers/FuzzNyquist+0x527512)
    #1 0x56ae67 in __gnu_cxx::new_allocator<float>::allocate(unsigned long, void const*) /usr/bin/../lib/gcc/x86_64-linux-gnu/8/../../../../include/c++/8/ext/new_allocator.h:111:27
    #2 0x56ad6c in std::allocator_traits<std::allocator<float> >::allocate(std::allocator<float>&, unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/8/../../../../include/c++/8/bits/alloc_traits.h:436:20
    #3 0x56a409 in std::_Vector_base<float, std::allocator<float> >::_M_allocate(unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/8/../../../../include/c++/8/bits/stl_vector.h:296:20
    #4 0x5696b5 in std::vector<float, std::allocator<float> >::_M_default_append(unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/8/../../../../include/c++/8/bits/vector.tcc:604:34
    #5 0x566e8c in std::vector<float, std::allocator<float> >::resize(unsigned long) /usr/bin/../lib/gcc/x86_64-linux-gnu/8/../../../../include/c++/8/bits/stl_vector.h:827:4
    #6 0x82076f in VorbisDecoderInternal::loadAudioData(void*, ov_callbacks) /home/ekse/git/libnyquist/builds/Fuzzing/../../src/VorbisDecoder.cpp:246:20
    #7 0x81ef9a in VorbisDecoderInternal::VorbisDecoderInternal(nqr::AudioData*, std::vector<unsigned char, std::allocator<unsigned char> > const&) /home/ekse/git/libnyquist/builds/Fuzzing/../../src/VorbisDecoder.cpp:56:13
    #8 0x81ea87 in nqr::VorbisDecoder::LoadFromBuffer(nqr::AudioData*, std::vector<unsigned char, std::allocator<unsigned char> > const&) /home/ekse/git/libnyquist/builds/Fuzzing/../../src/VorbisDecoder.cpp:264:27
    #9 0x5347bc in nqr::NyquistIO::Load(nqr::AudioData*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&, std::vector<unsigned char, std::allocator<unsigned char> > const&) /home/ekse/git/libnyquist/builds/Fuzzing/../../src/Common.cpp:133:22
    #10 0x52a6b3 in Fuzz_Decoder(unsigned char const*, unsigned long) /home/ekse/git/libnyquist/builds/Fuzzing/../../fuzzers/FuzzNyquist.cpp:20:12
    #11 0x52ad5b in LLVMFuzzerTestOneInput /home/ekse/git/libnyquist/builds/Fuzzing/../../fuzzers/FuzzNyquist.cpp:28:5
    #12 0x43231a in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/ekse/git/libnyquist/builds/Fuzzing/fuzzers/FuzzNyquist+0x43231a)
    #13 0x424c5c in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/home/ekse/git/libnyquist/builds/Fuzzing/fuzzers/FuzzNyquist+0x424c5c)
    #14 0x42a0e1 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/ekse/git/libnyquist/builds/Fuzzing/fuzzers/FuzzNyquist+0x42a0e1)
    #15 0x44c702 in main (/home/ekse/git/libnyquist/builds/Fuzzing/fuzzers/FuzzNyquist+0x44c702)
    #16 0x7fadf79f1b6a in __libc_start_main /build/glibc-KRRWSm/glibc-2.29/csu/../csu/libc-start.c:308:16

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/ekse/git/libnyquist/builds/Fuzzing/../../src/VorbisDecoder.cpp:105:49 in VorbisDecoderInternal::readInternal(unsigned long, unsigned long)
Shadow bytes around the buggy address:
  0x0c627fffcf70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c627fffcf80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c627fffcf90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c627fffcfa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c627fffcfb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c627fffcfc0:[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c627fffcfd0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c627fffcfe0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c627fffcff0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c627fffd000: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c627fffd010: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==12481==ABORTING
```