#!/usr/bin/env python3

from c.storage import Storage as StorageC
from python.src.storage import Storage as StoragePy

from hashlib import sha256


def hash(data):
    return sha256(data).hexdigest()[:16]


sc = StorageC()
sp = StoragePy()

for s in [sc, sp]:
    print(s.__class__)
    s.init()
    s.unlock(1)
    s.set(0xbeef, b"hello")
    s.set(0xcafe, b"world!")
    d = s._dump()
    print(d[0][:256], d[1][:256])
    print([hash(x) for x in d])
