"""Independent in-memory Git pack bytes and hashlib Git object IDs.
Fixture preparation only; no model output is scored here.
"""
from io import BytesIO
import hashlib,struct,zlib

def oid(data, algorithm='sha1', kind='blob'):
    return hashlib.new(algorithm,kind.encode()+b' '+str(len(data)).encode()+b'\0'+data).digest()

def size_varint(value):
    out=bytearray()
    while True:
        byte=value&127;value>>=7
        out.append(byte|(128 if value else 0))
        if not value:return bytes(out)

def delta(base, target):
    out=size_varint(len(base))+size_varint(len(target))
    for start in range(0,len(target),127):
        chunk=target[start:start+127];out+=bytes([len(chunk)])+chunk
    return out

def object_header(kind,length):
    first=(kind<<4)|(length&15);length>>=4;out=bytearray([first|(128 if length else 0)])
    while length:
        byte=length&127;length>>=7;out.append(byte|(128 if length else 0))
    return bytes(out)

def ofs_distance(value):
    assert value>0
    out=[value&127]
    while value>>7:
        value=(value>>7)-1;out.append(128|(value&127))
    return bytes(reversed(out))

def wire_pack(specs,algorithm='sha1'):
    """spec: kind=3/6/7, result=final bytes, payload=raw base or delta,
    REF additionally ref=binary oid; OFS additionally parent=earlier spec index.
    A caller may override index_oid for malformed-index regression cases.
    """
    body=bytearray(b'PACK'+struct.pack('>II',2,len(specs)));entries=[];offsets=[]
    for spec in specs:
        offset=len(body);offsets.append(offset);kind=spec['kind'];payload=spec['payload']
        prefix=b''
        if kind==6:prefix=ofs_distance(offset-offsets[spec['parent']])
        elif kind==7:prefix=spec['ref']
        encoded=object_header(kind,len(payload))+prefix+zlib.compress(payload)
        entries.append((spec.get('index_oid',oid(spec['result'],algorithm)),offset,zlib.crc32(encoded)&0xffffffff))
        body+=encoded
    checksum=hashlib.new(algorithm,body).digest()
    return bytes(body)+checksum,entries,offsets,checksum

def open_pack(specs,algorithm='sha1',resolver=None):
    from dulwich.object_format import get_object_format
    from dulwich.pack import Pack,PackData,MemoryPackIndex
    raw,entries,offsets,checksum=wire_pack(specs,algorithm)
    fmt=get_object_format(algorithm)
    data=PackData('memory.pack',fmt,file=BytesIO(raw))
    pack=Pack.from_objects(data,MemoryPackIndex(entries,fmt,pack_checksum=checksum))
    pack.resolve_ext_ref=resolver
    return pack,offsets

def controls():
    from dulwich.pack import apply_delta
    count=0
    for algorithm in ('sha1','sha256'):
        base=b'independent base';middle=b'middle payload';target=b'finished payload'
        d1=delta(base,middle);d2=delta(middle,target)
        assert b''.join(apply_delta(base,d1))==middle
        specs=[{'kind':3,'payload':base,'result':base},
               {'kind':6,'parent':0,'payload':d1,'result':middle},
               {'kind':7,'ref':oid(middle,algorithm),'payload':d2,'result':target}]
        pack,_=open_pack(specs,algorithm)
        try:
            assert pack.get_raw(oid(target,algorithm))==(3,target)
            assert pack.get_raw(oid(middle,algorithm))==(3,middle)
            count+=2
        finally:pack.close()
        calls=[]
        def resolver(requested):
            calls.append(requested)
            assert requested==oid(base,algorithm)
            return 3,[base]
        pack,_=open_pack([{'kind':7,'ref':oid(base,algorithm),'payload':delta(base,target),'result':target}],algorithm,resolver)
        try:
            assert pack.get_raw(oid(target,algorithm))==(3,target)
            assert calls==[oid(base,algorithm)];count+=1
        finally:pack.close()
    print('fixture positive controls:',count,'passed; independent SHA-1/SHA-256 IDs, mixed OFS/REF and external base')

if __name__=='__main__':controls()
