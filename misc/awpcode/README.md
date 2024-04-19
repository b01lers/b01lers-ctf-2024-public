# Writeup for awpcode by CygnusX

## View /solve/solve_builder.py

--- 

## Summary

The gist of this challenge is that python has an OOB read when co_names and co_const tuples are empty. 

For example, if I had the following opcode when co_names and co_const = ():

```
    0 LOAD_CONST               10 (None)
    2 RETURN_VALUE
```

Python would not cause an error, instead it goes to some offset 0x10 and grabs whatever is there.

## Finding something useful out of bounds

A simple script can be written to brute force all offsets up to 0xff and see if we find anything useful.
In this specific version, offset 0x73 has a builtins module, which we can use to get the flag.

Now we have a new issue, how to access this builtins module using no co_names or co_consts?

We can instead use the opcode `UNPACK_EX` to put the strings of all the keys of the builtins module onto the stack.
Then use the `BINARY_SUBSCR` opcode to get the value of that key in the builtins module.
Through this we are able to access arbitrary functions in the builtins module.

## Keeping our payload short enough
Popping many strings off the top of the stack is expensive characterwise, so we can use the `BUILD_MAP` opcode to speed up popping the strings off the stack, then just delete the map that it creates.

## Getting the flag
We can use the above information to call eval with input as a param.
```python
    eval(input())
```
This will allow us to run arbitrary python code:
```python
__import__('os').system('sh')
cat /flag.txt
```