# Writeup for pwnhub by CygnusX

---
## solve 

First thing we can notice is there is a 
```python
return render_template_string(f"Post contents here: {content[:250]}")
```
Which is clearly a flask ssti vulnerability. But there is some problems with that, we need to be an admin user to be able to view a post, and ontop of that there are a lot of weird restrictions for what we can post.

Another thing to notice is the flask secret key is only 20 bits long, which is easily brute-forceable.

I wrote a simple script to brute force the secret key, and used a tool called `flask-unsign` to create a new session cookie with my username as 'admin'.

Now that we are admin, we can view the posts we create. Problem is that there seems to be some error when you have a post longer than 20 chars. Note that a post is still created, even though an error is shown. The post id is easily findable, and we can access our posts!

All that is left is to find a way to read the flag without the restricted chars. You can use a trick where you store some of the restricted chars in other url params and combine that with a standard ssti payload to read the flag.

```python
{%with a=request|attr("args")|attr("get")("d"),b=request|attr("args")|attr("get")("f")%}{%print(request|attr("application")|attr(a~"globals"~a)|attr(a~"getitem"~a)(a~"builtins"~a)|attr(a~"getitem"~a)("open")(b)|attr("read")())%}{%endwith%}
```

Then we go to the following link: 
`/view/e5c478f7e0ea9f7e6dc8bcd722a3c93c4d849397b2e8c25ff283b95a8aa1eaa7?d=__&f=/flag.txt`
And we get the flag. An example is shown in `/solve`



