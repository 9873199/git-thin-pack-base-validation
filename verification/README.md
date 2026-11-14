# Git thin-pack resolver verification

Post-session AI-assisted independent review, separate from the original model tests. Python3.14.3, exact dependency-lock retained. Use a frozen checkout plus selected verification directory on PYTHONPATH. git-base-trust-r1: run python -B -m pytest -q test_git_pack_review.py,21 passed4 failed; model24 pass; upstream pack151 pass8 skipped, collection warning preserved. git-cache-hash-r2: run python -B -m pytest -q -s test_git_cache_hash_review.py,4 correct custom-base controls pass and4 wrong-content cache cases fail. These scopes overlap and are not summed. Hashlib IDs, pack headers, zlib payload, delta instructions and index are independently constructed by git_pack_fixture.py. Model-reported broader3636 pass/11 environment failures not independently repeated and not used as independent acceptance totals. No compiled accelerators or external service needed.

The demonstration is openly automated; character timings, whole-word correction and actual program output are retained. Program exit1 is a real observed trust-boundary failure. No product source changes after freeze.


冻结产物提交：https://github.com/9873199/git-thin-pack-base-validation/commit/797cd01f671c857887e9a17897e7016ee9de188a
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
