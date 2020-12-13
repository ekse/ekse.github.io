---
layout: post
title:  "Solving picoCTF 2013 Harder Serial with Z3"
date:   2014-08-10 00:00:00 -0400
categories: ctf,exploits
---

In the past weeks I have been watching LiveCTF, a project to livestream speedruns of wargames and CTF challenges. This is a great learning tool as you get to see the thought process of the caster as well as the tools and tricks they use to solve the challenges. 

I also recently learned about picoCTF, a capture the flag game made for high school teams organized by PPP.  I have been playing the 2013 edition in the last few days and it is actually really well made, for someone new to CTF I would definitely recommend starting with this one. It also has interesting challenges even for seasoned CTF players.

I decided to try to speedrun picoCTF and focus on optimizing my work process when going through the challenges. In this post I will show how to solve the 'Harder Serial' challenge using Z3.

![pico ctf](/assets/pico.png)

## The challenge

Harder Serial comes in the form of a Python script, we need to find a working serial for the RoboCorpIntergalactic software. The full script code is below.

```python
#!/usr/bin/env python
# Looks like the serial number verification for space ships is similar to that
# of your robot. Try to find a serial that verifies for this space ship

import sys
print ("Please enter a valid serial number from your RoboCorpIntergalactic purchase")
if len(sys.argv) < 2:
  print ("Usage: %s [serial number]"%sys.argv[0])
  exit()
  
print ("#>" + sys.argv[1] + "<#")

def check_serial(serial):
  if (not set(serial).issubset(set(map(str,range(10))))):
    print ("only numbers allowed")
    return False
  if len(serial) != 20:
    return False
  if int(serial[15]) + int(serial[4]) != 10:
    return False
  if int(serial[1]) * int(serial[18]) != 2:
    return False
  if int(serial[15]) / int(serial[9]) != 1:
    return False
  if int(serial[17]) - int(serial[0]) != 4:
    return False
  if int(serial[5]) - int(serial[17]) != -1:
    return False
  if int(serial[15]) - int(serial[1]) != 5:
    return False
  if int(serial[1]) * int(serial[10]) != 18:
    return False
  if int(serial[8]) + int(serial[13]) != 14:
    return False
  if int(serial[18]) * int(serial[8]) != 5:
    return False
  if int(serial[4]) * int(serial[11]) != 0:
    return False
  if int(serial[8]) + int(serial[9]) != 12:
    return False
  if int(serial[12]) - int(serial[19]) != 1:
    return False
  if int(serial[9]) % int(serial[17]) != 7:
    return False
  if int(serial[14]) * int(serial[16]) != 40:
    return False
  if int(serial[7]) - int(serial[4]) != 1:
    return False
  if int(serial[6]) + int(serial[0]) != 6:
    return False
  if int(serial[2]) - int(serial[16]) != 0:
    return False
  if int(serial[4]) - int(serial[6]) != 1:
    return False
  if int(serial[0]) % int(serial[5]) != 4:
    return False
  if int(serial[5]) * int(serial[11]) != 0:
    return False
  if int(serial[10]) % int(serial[15]) != 2:
    return False
  if int(serial[11]) / int(serial[3]) != 0:
    return False
  if int(serial[14]) - int(serial[13]) != -4:
    return False
  if int(serial[18]) + int(serial[19]) != 3:
    return False
  return True

if check_serial(sys.argv[1]):
  print ("Thank you! Your product has been verified!")
else:
  print ("I'm sorry that is incorrect. Please use a valid RoboCorpIntergalactic serial number")
```

As we can see the program expects a 20 digits serial and the `check_serial()` function checks a number of conditions on the values of the digits with simple operations. It probably can be solved by hand but it is a perfect use case for [Z3](https://github.com/Z3Prover/z3). In short, Z3 is an open-source theorem prover than allows us to define conditions to be met and will output if the conditions are satisfiable as well a set of values that meet all those conditions. The inner workings of Z3 and SMT solvers are a complex topic but Z3 itself is actually easy to use.

I will now go through my solution code, if you prefer to see the full script you can find it [here](https://github.com/ekse/code/blob/master/ctf/picoctf/harderserial/break_serial.py). Z3 uses its own syntax but luckily there are Python bindings which will make it easy to define the conditions. We start by importing z3 and defining integer variables for the serial digits.

```python
from z3 import *

# define the variables for the serial
s0 = Int('s[0]')
s1 = Int('s[1]')
s2 = Int('s[2]')
s3 = Int('s[3]')
s4 = Int('s[4]')
s5 = Int('s[5]')
s6 = Int('s[6]')
s7 = Int('s[7]')
s8 = Int('s[8]')
s9 = Int('s[9]')
s10 = Int('s[10]')
s11 = Int('s[11]')
s12 = Int('s[12]')
s13 = Int('s[13]')
s14 = Int('s[14]')
s15 = Int('s[15]')
s16 = Int('s[16]')
s17 = Int('s[17]')
s18 = Int('s[18]')
s19 = Int('s[19]')
```

Then we create an instance of the solver and add our conditions to it. The first set of conditions define the serial digits as values between 0 and 9.

```python
solver = Solver()

# all serial values are digits between 0 and 9
solver.add(s0 >= 0)
solver.add(s1 >= 0)
solver.add(s2 >= 0)
solver.add(s3 >= 0)
solver.add(s4 >= 0)
solver.add(s5 >= 0)
solver.add(s6 >= 0)
solver.add(s7 >= 0)
solver.add(s8 >= 0)
solver.add(s9 >= 0)
solver.add(s10 >= 0)
solver.add(s11 >= 0)
solver.add(s12 >= 0)
solver.add(s13 >= 0)
solver.add(s14 >= 0)
solver.add(s15 >= 0)
solver.add(s16 >= 0)
solver.add(s17 >= 0)
solver.add(s18 >= 0)
solver.add(s19 >= 0)
solver.add(s0 < 10)
solver.add(s1 < 10)
solver.add(s2 < 10)
solver.add(s3 < 10)
solver.add(s4 < 10)
solver.add(s5 < 10)
solver.add(s6 < 10)
solver.add(s7 < 10)
solver.add(s8 < 10)
solver.add(s9 < 10)
solver.add(s10 < 10)
solver.add(s11 < 10)
solver.add(s12 < 10)
solver.add(s13 < 10)
solver.add(s14 < 10)
solver.add(s15 < 10)
solver.add(s16 < 10)
solver.add(s17 < 10)
solver.add(s18 < 10)
solver.add(s19 < 10)
```

Then we add the conditions from the serial_check() function. To save time I used a couple of search and replace in a text editor to avoid typing them manually.

```python
# add serial checking conditions
solver.add(s15 + s4 == 10)
solver.add(s1 * s18 == 2 )
solver.add(s15 / s9 == 1)
solver.add(s17 - s0 == 4)
solver.add(s5 - s17 == -1)
solver.add(s15 - s1 == 5)
solver.add(s1 * s10 == 18)
solver.add(s8 + s13 == 14)
solver.add(s18 * s8 == 5)
solver.add(s4 * s11 == 0)
solver.add(s8 + s9 == 12)
solver.add(s12 - s19 == 1)
solver.add(s9 % s17 == 7)
solver.add(s14 * s16 == 40)
solver.add(s7 - s4 == 1)
solver.add(s6 + s0 == 6)
solver.add(s2 - s16 == 0)
solver.add(s4 - s6 == 1)
solver.add(s0 % s5 == 4)
solver.add(s5 * s11 == 0)
solver.add(s10 % s15 == 2)
solver.add(s11 / s3 == 0)
solver.add(s14 - s13 == -4)
solver.add(s18 + s19 == 3)
```

We add a condition to make `s[3]` different than zero because one of the conditions divides by it, Z3 will accept 0 as a valid value but Python will throw an exception. Finally we call `solver.check()` which will determine if the solver is able to meet the conditions and `solver.model()` which will return a set of values that meet those conditions.

```python
# s3 can't be 0 because of division by zero
solver.add(s3 != 0)

print("solving...")
print(solver.check())
print(solver.model())
```

```
>python break_serial.py
solving...
sat
[s[8] = 5,
 s[4] = 3,
 s[19] = 2,
 s[17] = 8,
 s[16] = 8,
 s[2] = 8,
 s[9] = 7,
 s[1] = 2,
 s[3] = 1,
 s[15] = 7,
 s[11] = 0,
 s[10] = 9,
 s[12] = 3,
 s[18] = 1,
 s[0] = 4,
 s[14] = 5,
 s[7] = 4,
 s[6] = 2,
 s[5] = 7,
 s[13] = 9]
```

Again with a bit of search/replace and some python we can get our serial.

```
>>> s = [0] * 20
>>> s[8] = 5
>>> s[4] = 3
>>> s[19] = 2
>>> s[17] = 8
>>> s[16] = 8
>>> s[2] = 8
>>> s[9] = 7
>>> s[1] = 2
>>> s[3] = 1
>>> s[15] = 7
>>> s[11] = 0
>>> s[10] = 9
>>> s[12] = 3
>>> s[18] = 1
>>> s[0] = 4
>>> s[14] = 5
>>> s[7] = 4
>>> s[6] = 2
>>> s[5] = 7
>>> s[13] = 9
>>> "".join([str(x) for x in s])
'42813724579039578812'
```

We validate that our key is accepted :

```
> python harder_serial.py 42813724579039578812
Please enter a valid serial number from your RoboCorpIntergalactic purchase
#>42813724579039578812<#

Thank you! Your product has been verified!
```

This was a rather simple use of Z3, for examples of advanced use of Z3 for reverse engineering see the following articles:

[Breaking Kryptonite's Obfuscation: A Static Analysis Approach Relying on Symbolic Execution](http://doar-e.github.io/blog/2013/09/16/breaking-kryptonites-obfuscation-with-symbolic-execution/) by Axel Souchet and
[Concolic execution - Taint analysis with Valgrind and constraints path solver with Z3](http://shell-storm.org/blog/Concolic-execution-taint-analysis-with-valgrind-and-constraints-path-solver-with-z3/) by Jonathan Salwan.

As always feel free to send me a message on Twitter if you have questions or comments! 

