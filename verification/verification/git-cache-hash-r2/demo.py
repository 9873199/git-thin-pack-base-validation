from git_pack_fixture import oid,open_pack
from test_git_cache_hash_review import copy_plus_suffix
from dulwich.pack import ExternalObjectMismatch
failed=0
for algorithm in ('sha1','sha256'):
    base=b'good base';wrong=b'evil base';target=base+b'!';wire=copy_plus_suffix(base,b'!');spec=[{'kind':7,'ref':oid(base,algorithm),'payload':wire,'result':target}]
    pack,offsets=open_pack(spec,algorithm,lambda key:(3,[base]))
    try:print(algorithm,'trusted resolver:',pack.get_raw(oid(target,algorithm))[1])
    finally:pack.close()
    pack,offsets=open_pack(spec,algorithm,lambda key:(3,[wrong]))
    try:
        try:pack.get_raw(oid(target,algorithm));print('default wrong hash: ACCEPTED');failed+=1
        except ExternalObjectMismatch:print('default wrong hash: rejected')
    finally:pack.close()
    pack,offsets=open_pack(spec,algorithm)
    try:
        try:
            pack.resolve_object(offsets[0],7,(oid(base,algorithm),[wire]),get_ref=lambda key:(None,3,[wrong]))
            actual=pack.get_raw(oid(target,algorithm))[1]
            print('custom get_ref returned:',actual)
            print('expected:',target,'cache hash valid:',oid(actual,algorithm)==oid(target,algorithm))
            if actual!=target:failed+=1
        except ExternalObjectMismatch:print('custom wrong hash: rejected')
    finally:pack.close()
print('Observed failing trust checks:',failed)
raise SystemExit(1 if failed else 0)
