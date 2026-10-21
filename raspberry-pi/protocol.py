"""Small protobuf wire readers; no keys or captured session data."""
def fields(data):
    def varint(pos):
        n = 0
        for shift in range(0, 70, 7):
            if pos >= len(data): raise ValueError('truncated varint')
            b = data[pos]; pos += 1; n |= (b & 127) << shift
            if b < 128: return n, pos
        raise ValueError('oversized varint')
    result = {}; pos = 0
    while pos < len(data):
        tag, pos = varint(pos); field, wire = tag >> 3, tag & 7
        if not field: raise ValueError('zero field')
        if wire == 0: value, pos = varint(pos)
        elif wire in (1, 2, 5):
            if wire == 2: size, pos = varint(pos)
            else: size = 8 if wire == 1 else 4
            if size > len(data) - pos: raise ValueError('truncated field')
            value = data[pos:pos+size]; pos += size
        else: raise ValueError('unsupported wire type')
        if field in result: raise ValueError('duplicate field')
        result[field] = value
    return result

def readvar(b, p):
    n=0
    for shift in range(0,70,7):
        if p>=len(b): raise ValueError('short varint')
        c=b[p]; p+=1; n|=(c&127)<<shift
        if c<128: return n,p
    raise ValueError('bad varint')
