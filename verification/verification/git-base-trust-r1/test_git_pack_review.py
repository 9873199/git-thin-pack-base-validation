"""Independent frozen-product review: real public Pack APIs, memory wire bytes.
This file is separate from the model's own tests and does not patch product code.
"""
import pytest
from git_pack_fixture import oid,delta,open_pack,size_varint
from dulwich.pack import (UnresolvedDeltas,DeltaCycle,ExternalObjectMismatch,
    ExternalObjectUnavailable,InvalidExternalReference,InvalidDeltaBaseOffset,
    MaxDeltaChainDepthExceeded)
from dulwich.errors import ApplyDeltaError

@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_external_valid_and_request_local_shared_base(algorithm):
    base=b'authorized base';one=b'first';two=b'second';bid=oid(base,algorithm);calls=[]
    def resolver(requested):calls.append(bytes(requested));return 3,[base]
    specs=[{'kind':7,'ref':bid,'payload':delta(base,x),'result':x} for x in (one,two)]
    pack,_=open_pack(specs,algorithm,resolver)
    try:
        assert pack.get_raw(oid(one,algorithm))==(3,one)
        assert pack.get_raw(oid(two,algorithm))==(3,two)
        assert calls==[bid,bid]
    finally:pack.close()

@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_mixed_chain_and_exact_depth(algorithm):
    base=b'base';middle=b'middle';target=b'target'
    specs=[{'kind':3,'payload':base,'result':base},
           {'kind':6,'parent':0,'payload':delta(base,middle),'result':middle},
           {'kind':7,'ref':oid(middle,algorithm),'payload':delta(middle,target),'result':target}]
    pack,_=open_pack(specs,algorithm)
    try:
        pack.max_delta_resolve_depth=2
        assert pack.get_raw(oid(target,algorithm))==(3,target)
    finally:pack.close()

@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_depth_rejects_before_external_fetch(algorithm):
    base=b'base';middle=b'middle';target=b'target';calls=[]
    specs=[{'kind':7,'ref':oid(base,algorithm),'payload':delta(base,middle),'result':middle},
           {'kind':6,'parent':0,'payload':delta(middle,target),'result':target}]
    def resolver(requested):calls.append(requested);return 3,[base]
    pack,_=open_pack(specs,algorithm,resolver)
    try:
        pack.max_delta_resolve_depth=1
        with pytest.raises(MaxDeltaChainDepthExceeded):pack.get_raw(oid(target,algorithm))
        assert calls==[]
    finally:pack.close()

@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_offsetless_three_node_cycle_single_fetch(algorithm):
    base=b'a';target=b'b';d=[delta(base,target)];ids=[bytes([i])*len(oid(base,algorithm)) for i in (1,2,3)]
    pack,offsets=open_pack([{'kind':7,'ref':ids[0],'payload':d[0],'result':target}],algorithm)
    calls=[]
    def lookup(requested):
        calls.append(bytes(requested));i=ids.index(bytes(requested));return None,7,(ids[(i+1)%3],d)
    try:
        with pytest.raises(DeltaCycle):pack.resolve_object(offsets[0],7,(ids[0],d),get_ref=lookup)
        assert calls==ids
    finally:pack.close()

@pytest.mark.parametrize('bad_distance',[0,-1,100000])
def test_bad_ofs_offsets_are_library_errors(bad_distance):
    pack,offsets=open_pack([{'kind':3,'payload':b'base','result':b'base'}])
    try:
        with pytest.raises(InvalidDeltaBaseOffset):pack.resolve_object(offsets[0],6,(bad_distance,[delta(b'base',b'changed')]))
    finally:pack.close()

@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_default_external_hash_failure_preserves_cache(algorithm):
    base=b'good base';wrong=b'evil base';target=b'target';existing=b'keep'
    pack,offsets=open_pack([{'kind':3,'payload':existing,'result':existing},
        {'kind':7,'ref':oid(base,algorithm),'payload':delta(base,target),'result':target}],algorithm,lambda requested:(3,[wrong]))
    try:
        assert pack.get_raw(oid(existing,algorithm))==(3,existing)
        before=dict(pack.data._offset_cache.items())
        with pytest.raises(ExternalObjectMismatch):pack.get_raw(oid(target,algorithm))
        assert dict(pack.data._offset_cache.items())==before
    finally:pack.close()

@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_custom_offsetless_full_base_must_be_hashed(algorithm):
    base=b'good base';wrong=b'evil base';target=b'target'
    pack,offsets=open_pack([{'kind':7,'ref':oid(base,algorithm),'payload':delta(base,target),'result':target}],algorithm)
    try:
        with pytest.raises(ExternalObjectMismatch):
            pack.resolve_object(offsets[0],7,(oid(base,algorithm),[delta(base,target)]),get_ref=lambda requested:(None,3,[wrong]))
    finally:pack.close()

@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_custom_offsetless_resolved_delta_must_be_hashed(algorithm):
    base=b'base';middle=b'good';wrong=b'evil';target=b'done';bid=oid(base,algorithm);mid=oid(middle,algorithm)
    pack,offsets=open_pack([{'kind':7,'ref':mid,'payload':delta(middle,target),'result':target}],algorithm)
    def lookup(requested):
        if requested==mid:return None,7,(bid,[delta(base,wrong)])
        assert requested==bid
        return None,3,[base]
    try:
        with pytest.raises(ExternalObjectMismatch):pack.resolve_object(offsets[0],7,(mid,[delta(middle,target)]),get_ref=lookup)
    finally:pack.close()

@pytest.mark.parametrize('reply',[None,(None,b'x'),(7,[b'x']),(3,[1]),(False,b'x')])
def test_default_malformed_external_types_rejected(reply):
    base=b'base';target=b'target';pack,_=open_pack([{'kind':7,'ref':oid(base),'payload':delta(base,target),'result':target}],resolver=lambda requested:reply)
    try:
        with pytest.raises(InvalidExternalReference):pack.get_raw(oid(target))
    finally:pack.close()

def test_resolver_performance_failure_preserved():
    base=b'base';target=b'target';error=TimeoutError('synthetic controlled timeout')
    def resolver(requested):raise error
    pack,_=open_pack([{'kind':7,'ref':oid(base),'payload':delta(base,target),'result':target}],resolver=resolver)
    try:
        with pytest.raises(TimeoutError) as caught:pack.get_raw(oid(target))
        assert caught.value is error
    finally:pack.close()

def test_missing_default_external_is_distinguishable():
    base=b'base';target=b'target'
    def resolver(requested):raise KeyError(requested)
    pack,_=open_pack([{'kind':7,'ref':oid(base),'payload':delta(base,target),'result':target}],resolver=resolver)
    try:
        with pytest.raises(ExternalObjectUnavailable):pack.get_raw(oid(target))
    finally:pack.close()

def test_delta_apply_failure_keeps_existing_and_no_intermediate_cache():
    base=b'base';middle=b'middle';bad=b'bad';old=b'old'
    specs=[{'kind':3,'payload':old,'result':old},
           {'kind':3,'payload':base,'result':base},
           {'kind':6,'parent':1,'payload':delta(base,middle),'result':middle},
           {'kind':6,'parent':2,'payload':b'\x00\x01\x00','result':bad}]
    pack,_=open_pack(specs)
    try:
        assert pack.get_raw(oid(old))==(3,old)
        before=dict(pack.data._offset_cache.items())
        with pytest.raises(ApplyDeltaError):pack.get_raw(oid(bad))
        assert dict(pack.data._offset_cache.items())==before
    finally:pack.close()
