import pytest
from git_pack_fixture import oid,delta,open_pack,size_varint
from dulwich.pack import ExternalObjectMismatch

def copy_plus_suffix(base,suffix):
    assert 0<len(base)<256 and len(suffix)<128
    return size_varint(len(base))+size_varint(len(base)+len(suffix))+bytes([0x90,len(base),len(suffix)])+suffix

@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_correct_custom_base_is_valid(algorithm):
    base=b'good base';target=base+b'!';d=[copy_plus_suffix(base,b'!')]
    pack,offsets=open_pack([{'kind':7,'ref':oid(base,algorithm),'payload':d[0],'result':target}],algorithm)
    try:
        kind,chunks=pack.resolve_object(offsets[0],7,(oid(base,algorithm),d),get_ref=lambda key:(None,3,[base]))
        assert kind==3 and b''.join(chunks)==target
    finally:pack.close()

@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_wrong_custom_base_cannot_poison_public_get_raw(algorithm):
    base=b'good base';wrong=b'evil base';target=base+b'!';d=[copy_plus_suffix(base,b'!')]
    pack,offsets=open_pack([{'kind':7,'ref':oid(base,algorithm),'payload':d[0],'result':target}],algorithm)
    try:
        try:pack.resolve_object(offsets[0],7,(oid(base,algorithm),d),get_ref=lambda key:(None,3,[wrong]))
        except ExternalObjectMismatch:return
        actual=pack.get_raw(oid(target,algorithm))[1]
        print('algorithm',algorithm,'requested',target,'actual cached bytes',actual,'actual_oid_matches_requested',oid(actual,algorithm)==oid(target,algorithm))
        pytest.fail('wrong external base accepted and shared cache returns '+repr(actual))
    finally:pack.close()

@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_wrong_custom_delta_result_cannot_poison_cache(algorithm):
    base=b'base';middle=b'good';wrong=b'evil';target=middle+b'!';bid=oid(base,algorithm);mid=oid(middle,algorithm);d=[copy_plus_suffix(middle,b'!')]
    pack,offsets=open_pack([{'kind':7,'ref':mid,'payload':d[0],'result':target}],algorithm)
    def lookup(key):
        if key==mid:return None,7,(bid,[delta(base,wrong)])
        assert key==bid
        return None,3,[base]
    try:
        try:pack.resolve_object(offsets[0],7,(mid,d),get_ref=lookup)
        except ExternalObjectMismatch:return
        actual=pack.get_raw(oid(target,algorithm))[1]
        print('algorithm',algorithm,'requested',target,'actual cached bytes',actual,'actual_oid_matches_requested',oid(actual,algorithm)==oid(target,algorithm))
        pytest.fail('external delta result hash unchecked and cache returns '+repr(actual))
    finally:pack.close()

@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_correct_custom_delta_chain_valid(algorithm):
    base=b'base';middle=b'good';target=middle+b'!';bid=oid(base,algorithm);mid=oid(middle,algorithm);d=[copy_plus_suffix(middle,b'!')]
    pack,offsets=open_pack([{'kind':7,'ref':mid,'payload':d[0],'result':target}],algorithm)
    def lookup(key):
        if key==mid:return None,7,(bid,[delta(base,middle)])
        assert key==bid
        return None,3,[base]
    try:
        kind,chunks=pack.resolve_object(offsets[0],7,(mid,d),get_ref=lookup)
        assert kind==3 and b''.join(chunks)==target
    finally:pack.close()
