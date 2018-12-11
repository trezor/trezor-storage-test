uid = b"\x67\xce\x6a\xe8\xf7\x9b\x73\x96\x83\x88\x21\x5e"


def memory_equals(sc, sp) -> bool:
    return sc._dump() == sp._dump()
