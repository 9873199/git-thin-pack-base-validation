# test_pack_resolve_hardening.py -- Tests for hardened delta resolution
# against untrusted external base resolvers.
# Copyright (C) 2026 The Dulwich contributors
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Dulwich is dual-licensed under the Apache License, Version 2.0 and the GNU
# General Public License as published by the Free Software Foundation; version 2.0
# or (at your option) any later version. You can redistribute it and/or
# modify it under the terms of either of these two licenses.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# You should have received a copy of the licenses; if not, see
# <http://www.gnu.org/licenses/> for a copy of the GNU General Public License
# and <http://www.apache.org/licenses/LICENSE-2.0> for a copy of the Apache
# License, Version 2.0.
#

# Every pack here is built entirely in memory (BytesIO + MemoryPackIndex)
# and every external base comes from a resolver constructed inside the
# test, so nothing touches the network or the on-disk object store.

from hashlib import sha256
from io import BytesIO

from dulwich.object_format import SHA1, SHA256, ObjectFormat
from dulwich.errors import ApplyDeltaError
from dulwich.objects import Blob
from dulwich.pack import (
    OFS_DELTA,
    REF_DELTA,
    DeltaCycle,
    ExternalObjectMismatch,
    ExternalObjectUnavailable,
    InvalidDeltaBaseOffset,
    InvalidExternalReference,
    MaxDeltaChainDepthExceeded,
    MemoryPackIndex,
    Pack,
    PackData,
    UnresolvedDeltas,
    create_delta,
    obj_sha,
    write_pack_header,
    write_pack_object,
)

from . import TestCase


BLOB = Blob.type_num


def _oid(fmt: ObjectFormat, type_num: int, data: bytes) -> bytes:
    return obj_sha(type_num, data, fmt.hash_func)


def _delta(base: bytes, target: bytes) -> list[bytes]:
    return list(create_delta(base, target))


def build_inmemory_pack(fmt: ObjectFormat, specs):
    """Build a self contained pack from compact object specs.

    Each spec is ``(type_num, pack_obj, target_sha)`` where ``target_sha``
    is the id the object has once its delta chain is resolved (the id the
    index maps to its offset).
    """
    buf = BytesIO()
    write_pack_header(buf.write, len(specs))
    entries = []
    offsets = []
    for type_num, pack_obj, target_sha in specs:
        offset = buf.tell()
        crc = write_pack_object(buf.write, type_num, pack_obj, object_format=fmt)
        offsets.append(offset)
        entries.append((target_sha, offset, crc))
    body = buf.getvalue()
    trailer = fmt.hash_object(body)
    data = PackData(
        "hardening.pack", file=BytesIO(body + trailer), object_format=fmt
    )
    index = MemoryPackIndex(entries, fmt, pack_checksum=trailer)
    pack = Pack.from_objects(data, index)
    return pack, offsets, data, index


class CountingResolver:
    """Resolver stand-in that records every id it is asked for."""

    def __init__(self, mapping):
        self.mapping = dict(mapping)
        self.calls: list[bytes] = []

    def __call__(self, sha):
        self.calls.append(bytes(sha))
        try:
            return self.mapping[bytes(sha)]
        except KeyError:
            raise KeyError(sha) from None


class ResolveObjectHardeningTests(TestCase):
    """SHA-1 hardening scenarios driven through the public entry points."""

    def setUp(self) -> None:
        super().setUp()
        self.fmt = SHA1
        # A well known external base blob and its real id.
        self.base_data = b"base object contents"
        self.base_id = _oid(self.fmt, BLOB, self.base_data)

    # ------------------------------------------------------------------
    # Happy path / sharing
    # ------------------------------------------------------------------
    def test_thin_pack_external_base_resolves(self) -> None:
        target = b"base object contents, extended"
        pack, offsets, _, _ = build_inmemory_pack(
            self.fmt,
            [
                (
                    REF_DELTA,
                    (self.base_id, _delta(self.base_data, target)),
                    _oid(self.fmt, BLOB, target),
                )
            ],
        )
        self.addCleanup(pack.close)
        resolver = CountingResolver({self.base_id: (BLOB, self.base_data)})
        pack.resolve_ext_ref = resolver
        self.assertEqual(
            (BLOB, target), pack.get_raw(_oid(self.fmt, BLOB, target))
        )
        # The external id was fetched exactly once.
        self.assertEqual([self.base_id], resolver.calls)

    def test_resolver_may_return_bytes_or_chunks(self) -> None:
        target = self.base_data + b"!"
        pack, _, _, _ = build_inmemory_pack(
            self.fmt,
            [
                (
                    REF_DELTA,
                    (self.base_id, _delta(self.base_data, target)),
                    _oid(self.fmt, BLOB, target),
                )
            ],
        )
        self.addCleanup(pack.close)
        pack.resolve_ext_ref = CountingResolver(
            {self.base_id: (BLOB, [self.base_data])}
        )
        self.assertEqual(
            (BLOB, target), pack.get_raw(_oid(self.fmt, BLOB, target))
        )

    def test_shared_external_base_is_not_a_cycle(self) -> None:
        # Two independent deltas both build on the same external base. Each
        # resolution may fetch that base once, but the per-request visit set
        # must not leak, so the second request is not falsely seen as a loop.
        t1 = self.base_data + b" one"
        t2 = self.base_data + b" two"
        pack, _, _, _ = build_inmemory_pack(
            self.fmt,
            [
                (
                    REF_DELTA,
                    (self.base_id, _delta(self.base_data, t1)),
                    _oid(self.fmt, BLOB, t1),
                ),
                (
                    REF_DELTA,
                    (self.base_id, _delta(self.base_data, t2)),
                    _oid(self.fmt, BLOB, t2),
                ),
            ],
        )
        self.addCleanup(pack.close)
        resolver = CountingResolver({self.base_id: (BLOB, self.base_data)})
        pack.resolve_ext_ref = resolver

        self.assertEqual((BLOB, t1), pack.get_raw(_oid(self.fmt, BLOB, t1)))
        self.assertEqual((BLOB, t2), pack.get_raw(_oid(self.fmt, BLOB, t2)))
        # One fetch per request, no state carried over between them.
        self.assertEqual([self.base_id, self.base_id], resolver.calls)

    def test_shared_internal_base_is_reused(self) -> None:
        # Diamond inside one pack: two OFS deltas share one full base.
        d1 = self.base_data + b"#1"
        d2 = self.base_data + b"#2"
        id_b = self.base_id
        id1 = _oid(self.fmt, BLOB, d1)
        id2 = _oid(self.fmt, BLOB, d2)
        buf = BytesIO()
        write_pack_header(buf.write, 3)
        o_base = buf.tell()
        write_pack_object(buf.write, BLOB, self.base_data, object_format=self.fmt)
        o1 = buf.tell()
        write_pack_object(
            buf.write,
            OFS_DELTA,
            (o1 - o_base, _delta(self.base_data, d1)),
            object_format=self.fmt,
        )
        o2 = buf.tell()
        write_pack_object(
            buf.write,
            OFS_DELTA,
            (o2 - o_base, _delta(self.base_data, d2)),
            object_format=self.fmt,
        )
        body = buf.getvalue()
        trailer = self.fmt.hash_object(body)
        data = PackData(
            "shared.pack", file=BytesIO(body + trailer), object_format=self.fmt
        )
        self.addCleanup(data.close)
        index = MemoryPackIndex(
            [(id_b, o_base, 0), (id1, o1, 0), (id2, o2, 0)],
            self.fmt,
            pack_checksum=trailer,
        )
        pack = Pack.from_objects(data, index)
        self.addCleanup(pack.close)
        # Two independent chains sharing one base are both fine; the base is
        # reused, not mistaken for a cycle.
        self.assertEqual((BLOB, d1), pack.get_raw(id1))
        self.assertEqual((BLOB, d2), pack.get_raw(id2))

    # ------------------------------------------------------------------
    # Cycles
    # ------------------------------------------------------------------
    def test_external_self_loop_without_offset(self) -> None:
        # Every get_ref reply carries offset=None, yet the self reference
        # must be caught via the object-id visit set.
        x = b"\x11" * 20
        delta = _delta(b"a", b"a")
        pack, offsets, _, _ = build_inmemory_pack(
            self.fmt,
            [
                (
                    REF_DELTA,
                    (x, delta),
                    b"\xcc" * 20,
                )
            ],
        )
        self.addCleanup(pack.close)

        def get_ref(sha):
            # The "external" object is itself a REF delta naming the same id.
            return None, REF_DELTA, (bytes(sha), delta)

        with self.assertRaises(DeltaCycle) as cm:
            pack.resolve_object(
                offsets[0], REF_DELTA, (x, delta), get_ref=get_ref
            )
        self.assertEqual([x], cm.exception.shas)

    def test_external_long_loop_without_offset(self) -> None:
        x1, x2, x3 = b"\x01" * 20, b"\x02" * 20, b"\x03" * 20
        delta = _delta(b"a", b"a")
        chain = {
            x1: (None, REF_DELTA, (x2, delta)),
            x2: (None, REF_DELTA, (x3, delta)),
            x3: (None, REF_DELTA, (x1, delta)),
        }
        calls = []

        def get_ref(sha):
            calls.append(bytes(sha))
            return chain[bytes(sha)]

        pack, offsets, _, _ = build_inmemory_pack(
            self.fmt, [(REF_DELTA, (x1, delta), b"\xcc" * 20)]
        )
        self.addCleanup(pack.close)
        with self.assertRaises(DeltaCycle):
            pack.resolve_object(
                offsets[0], REF_DELTA, (x1, delta), get_ref=get_ref
            )
        # x1 is reached a second time through the chain and rejected before
        # any further lookup: exactly the three distinct ids were fetched.
        self.assertEqual([x1, x2, x3], calls)

    def test_mixed_ofs_ref_cycle_through_get_raw(self) -> None:
        # O0 is a REF delta naming O2; O2/O1 are OFS deltas walking back to
        # O0. The chain mixes both delta kinds and closes on the start.
        o0_data, o1_data, o2_data = b"o0", b"o1", b"o2"
        id0, id1, id2 = (
            _oid(self.fmt, BLOB, o0_data),
            _oid(self.fmt, BLOB, o1_data),
            _oid(self.fmt, BLOB, o2_data),
        )
        # Lay out a placeholder first object so real offsets are known, then
        # build the pack with correct relative offsets.
        pre = BytesIO()
        write_pack_header(pre.write, 3)
        o0_offset = pre.tell()
        write_pack_object(
            pre.write, REF_DELTA, (id2, _delta(o2_data, o0_data)),
            object_format=self.fmt,
        )
        o1_offset = pre.tell()
        write_pack_object(
            pre.write,
            OFS_DELTA,
            (o1_offset - o0_offset, _delta(o0_data, o1_data)),
            object_format=self.fmt,
        )
        o2_offset = pre.tell()
        write_pack_object(
            pre.write,
            OFS_DELTA,
            (o2_offset - o1_offset, _delta(o1_data, o2_data)),
            object_format=self.fmt,
        )
        body = pre.getvalue()
        trailer = self.fmt.hash_object(body)
        data = PackData(
            "mixed.pack", file=BytesIO(body + trailer), object_format=self.fmt
        )
        self.addCleanup(data.close)
        index = MemoryPackIndex(
            [(id0, o0_offset, 0), (id1, o1_offset, 0), (id2, o2_offset, 0)],
            self.fmt,
            pack_checksum=trailer,
        )
        pack = Pack.from_objects(data, index)
        self.addCleanup(pack.close)
        with self.assertRaises(DeltaCycle):
            pack.get_raw(id0)

    # ------------------------------------------------------------------
    # OFS_DELTA offset validation
    # ------------------------------------------------------------------
    def test_ofs_delta_zero_and_negative_rejected(self) -> None:
        # A real, readable pack gives us genuine offsets; the bad OFS tuples
        # are handed to resolve_object directly so no re-parse is needed.
        other = self.base_data + b" sibling"
        buf = BytesIO()
        write_pack_header(buf.write, 2)
        o_base = buf.tell()
        write_pack_object(buf.write, BLOB, self.base_data, object_format=self.fmt)
        o_delta = buf.tell()
        write_pack_object(buf.write, BLOB, other, object_format=self.fmt)
        body = buf.getvalue()
        trailer = self.fmt.hash_object(body)
        data = PackData(
            "ofs.pack", file=BytesIO(body + trailer), object_format=self.fmt
        )
        self.addCleanup(data.close)
        index = MemoryPackIndex(
            [
                (self.base_id, o_base, 0),
                (_oid(self.fmt, BLOB, other), o_delta, 0),
            ],
            self.fmt,
            pack_checksum=trailer,
        )
        pack = Pack.from_objects(data, index)
        self.addCleanup(pack.close)
        delta = _delta(self.base_data, self.base_data)
        # rel == 0 references the object itself; rel == o_delta lands at 0.
        for rel in (0, o_delta):
            with self.assertRaises(InvalidDeltaBaseOffset):
                pack.resolve_object(o_delta, OFS_DELTA, (rel, delta))
        # A negative encoded offset is likewise rejected.
        with self.assertRaises(InvalidDeltaBaseOffset):
            pack.resolve_object(o_delta, OFS_DELTA, (-5, delta))

    def test_ofs_delta_unindexed_position_rejected(self) -> None:
        other = self.base_data + b" sibling"
        buf = BytesIO()
        write_pack_header(buf.write, 2)
        o_base = buf.tell()
        write_pack_object(buf.write, BLOB, self.base_data, object_format=self.fmt)
        o_delta = buf.tell()
        write_pack_object(buf.write, BLOB, other, object_format=self.fmt)
        body = buf.getvalue()
        trailer = self.fmt.hash_object(body)
        data = PackData(
            "ofs-gap.pack", file=BytesIO(body + trailer), object_format=self.fmt
        )
        self.addCleanup(data.close)
        index = MemoryPackIndex(
            [
                (self.base_id, o_base, 0),
                (_oid(self.fmt, BLOB, other), o_delta, 0),
            ],
            self.fmt,
            pack_checksum=trailer,
        )
        pack = Pack.from_objects(data, index)
        self.addCleanup(pack.close)
        delta = _delta(other, other)
        # Aim the base one byte into the first object: within range and
        # strictly backwards, but not an object boundary in the index.
        bad_rel = o_delta - (o_base + 1)
        with self.assertRaises(InvalidDeltaBaseOffset):
            pack.resolve_object(o_delta, OFS_DELTA, (bad_rel, delta))

    # ------------------------------------------------------------------
    # External resolver validation
    # ------------------------------------------------------------------
    def test_external_wrong_hash_rejected(self) -> None:
        target = self.base_data + b"!!"
        pack, offsets, _, _ = build_inmemory_pack(
            self.fmt,
            [
                (
                    REF_DELTA,
                    (self.base_id, _delta(self.base_data, target)),
                    _oid(self.fmt, BLOB, target),
                )
            ],
        )
        self.addCleanup(pack.close)
        # Plausible bytes, but they do not hash to the requested id.
        pack.resolve_ext_ref = CountingResolver(
            {self.base_id: (BLOB, b"totally different contents")}
        )
        with self.assertRaises(ExternalObjectMismatch) as cm:
            pack.get_raw(_oid(self.fmt, BLOB, target))
        self.assertEqual(self.base_id, cm.exception.sha)
        self.assertNotEqual(self.base_id, cm.exception.actual_sha)
        # Nothing was cached for the object whose resolution failed.
        with self.assertRaises(KeyError):
            pack.data._get_cached_object_at(offsets[0])

    def test_external_wrong_type_rejected(self) -> None:
        target = self.base_data + b"!!"
        pack, _, _, _ = build_inmemory_pack(
            self.fmt,
            [
                (
                    REF_DELTA,
                    (self.base_id, _delta(self.base_data, target)),
                    _oid(self.fmt, BLOB, target),
                )
            ],
        )
        self.addCleanup(pack.close)
        for bad_type in (REF_DELTA, 9, 0):
            pack.resolve_ext_ref = CountingResolver(
                {self.base_id: (bad_type, self.base_data)}
            )
            with self.assertRaises(InvalidExternalReference):
                pack.get_raw(_oid(self.fmt, BLOB, target))

    def test_external_missing_is_distinguishable(self) -> None:
        target = self.base_data + b"!!"
        pack, _, _, _ = build_inmemory_pack(
            self.fmt,
            [
                (
                    REF_DELTA,
                    (self.base_id, _delta(self.base_data, target)),
                    _oid(self.fmt, BLOB, target),
                )
            ],
        )
        self.addCleanup(pack.close)

        def raising(sha):
            raise KeyError(sha)

        pack.resolve_ext_ref = raising
        with self.assertRaises(ExternalObjectUnavailable):
            pack.get_raw(_oid(self.fmt, BLOB, target))

        # With no resolver at all the historical KeyError contract holds.
        pack.resolve_ext_ref = None
        with self.assertRaises(KeyError):
            pack.get_raw(_oid(self.fmt, BLOB, target))

    def test_external_malformed_replies_never_raise_bare_errors(self) -> None:
        target = self.base_data + b"!!"
        pack, _, _, _ = build_inmemory_pack(
            self.fmt,
            [
                (
                    REF_DELTA,
                    (self.base_id, _delta(self.base_data, target)),
                    _oid(self.fmt, BLOB, target),
                )
            ],
        )
        self.addCleanup(pack.close)
        bad_replies = [
            (3,),  # not a pair
            (BLOB, self.base_data, b"extra"),  # triple
            "not a tuple",
            None,  # no reply at all
            (BLOB, "not bytes"),  # wrong contents type
            (BLOB, [b"mixed", 7]),  # non-bytes chunk
            (BLOB, None),
        ]
        target_id = _oid(self.fmt, BLOB, target)
        for reply in bad_replies:
            pack.resolve_ext_ref = CountingResolver({self.base_id: reply})
            with self.assertRaises(InvalidExternalReference):
                pack.get_raw(target_id)

    def test_resolver_failure_is_not_mistaken_for_bad_data(self) -> None:
        # A healthy resolver that hits a transient/performance failure must
        # surface its own exception, not be reclassified as a malformed
        # external reference.
        target = self.base_data + b"!!"
        pack, _, _, _ = build_inmemory_pack(
            self.fmt,
            [
                (
                    REF_DELTA,
                    (self.base_id, _delta(self.base_data, target)),
                    _oid(self.fmt, BLOB, target),
                )
            ],
        )
        self.addCleanup(pack.close)

        class ResolverTimeout(RuntimeError):
            pass

        def flaky(sha):
            raise ResolverTimeout("temporary resolver overload")

        pack.resolve_ext_ref = flaky
        with self.assertRaises(ResolverTimeout):
            pack.get_raw(_oid(self.fmt, BLOB, target))

    def test_ref_delta_bad_id_length(self) -> None:
        pack, offsets, _, _ = build_inmemory_pack(
            self.fmt, [(BLOB, self.base_data, self.base_id)]
        )
        self.addCleanup(pack.close)
        short_id = b"\xab" * 7
        with self.assertRaises(InvalidExternalReference):
            pack.resolve_object(
                offsets[0],
                REF_DELTA,
                (short_id, _delta(self.base_data, self.base_data)),
            )

    # ------------------------------------------------------------------
    # Depth limit
    # ------------------------------------------------------------------
    def _external_chain_pack(self, length):
        # Pack object is a REF delta naming x1; get_ref walks x1..xlength,
        # each an external REF delta (offset None), ending in a full blob.
        ids = [bytes([i + 1]) * 20 for i in range(length)]
        terminal_data = b"terminal"
        delta = _delta(terminal_data, terminal_data)
        chain = {}
        for i in range(length - 1):
            chain[ids[i]] = (None, REF_DELTA, (ids[i + 1], delta))
        chain[ids[-1]] = (None, BLOB, [terminal_data])
        calls = []

        def get_ref(sha):
            calls.append(bytes(sha))
            return chain[bytes(sha)]

        pack, offsets, _, _ = build_inmemory_pack(
            self.fmt, [(REF_DELTA, (ids[0], delta), b"\xee" * 20)]
        )
        self.addCleanup(pack.close)
        return pack, offsets[0], ids[0], delta, get_ref, calls, terminal_data

    def test_depth_limit_allows_exactly_the_limit(self) -> None:
        limit = 3
        pack, offset, first_id, delta, get_ref, _, terminal = (
            self._external_chain_pack(limit)
        )
        pack.max_delta_resolve_depth = limit
        type_num, chunks = pack.resolve_object(
            offset, REF_DELTA, (first_id, delta), get_ref=get_ref
        )
        self.assertEqual(BLOB, type_num)
        self.assertEqual(terminal, b"".join(chunks))

    def test_depth_limit_rejects_next_level_before_fetching(self) -> None:
        limit = 3
        pack, offset, first_id, delta, get_ref, calls, _ = (
            self._external_chain_pack(limit + 1)
        )
        pack.max_delta_resolve_depth = limit
        with self.assertRaises(MaxDeltaChainDepthExceeded) as cm:
            pack.resolve_object(
                offset, REF_DELTA, (first_id, delta), get_ref=get_ref
            )
        self.assertEqual(limit, cm.exception.limit)
        # The (limit+1)th node is refused before its resolver call: exactly
        # limit external lookups happened, and the final id was never asked.
        self.assertEqual(limit, len(calls))

    # ------------------------------------------------------------------
    # Cache isolation
    # ------------------------------------------------------------------
    def test_failed_resolution_keeps_valid_cache_and_adds_nothing(self) -> None:
        d1 = self.base_data + b"#1"
        id1 = _oid(self.fmt, BLOB, d1)
        buf = BytesIO()
        write_pack_header(buf.write, 2)
        o_base = buf.tell()
        write_pack_object(buf.write, BLOB, self.base_data, object_format=self.fmt)
        o_delta = buf.tell()
        write_pack_object(
            buf.write,
            OFS_DELTA,
            (o_delta - o_base, _delta(self.base_data, d1)),
            object_format=self.fmt,
        )
        body = buf.getvalue()
        trailer = self.fmt.hash_object(body)
        data = PackData(
            "cache.pack", file=BytesIO(body + trailer), object_format=self.fmt
        )
        self.addCleanup(data.close)
        index = MemoryPackIndex(
            [(self.base_id, o_base, 0), (id1, o_delta, 0)],
            self.fmt,
            pack_checksum=trailer,
        )
        pack = Pack.from_objects(data, index)
        self.addCleanup(pack.close)
        # A successful resolution caches the resolved delta object at O1.
        self.assertEqual((BLOB, d1), pack.get_raw(id1))
        cached_type, cached_chunks = pack.data._get_cached_object_at(o_delta)
        self.assertEqual(BLOB, cached_type)
        self.assertEqual(d1, b"".join(cached_chunks))

        # Now a second, failing resolution through a missing external base.
        bad_id = b"\x7f" * 20
        bad_target = b"bad target"
        pack.resolve_ext_ref = CountingResolver({})  # always raises KeyError
        with self.assertRaises(UnresolvedDeltas):
            pack.resolve_object(
                o_delta,
                REF_DELTA,
                (bad_id, _delta(b"x", bad_target)),
            )

        # The pre-existing valid cache entry is untouched, and nothing was
        # stored for the failed external reference.
        still_type, still_chunks = pack.data._get_cached_object_at(o_delta)
        self.assertEqual(cached_type, still_type)
        self.assertEqual(b"".join(cached_chunks), b"".join(still_chunks))

    def test_apply_delta_failure_does_not_cache_intermediates(self) -> None:
        # A chain whose OFS offset is valid but whose delta instructions are
        # broken must surface ApplyDeltaError and leave nothing in the cache.
        buf = BytesIO()
        write_pack_header(buf.write, 2)
        o_base = buf.tell()
        write_pack_object(buf.write, BLOB, self.base_data, object_format=self.fmt)
        o_delta = buf.tell()
        broken = [b"\x05\x03this header claims a 5 byte base, it is not 20"]
        write_pack_object(
            buf.write,
            OFS_DELTA,
            (o_delta - o_base, broken),
            object_format=self.fmt,
        )
        body = buf.getvalue()
        trailer = self.fmt.hash_object(body)
        data = PackData(
            "broken-delta.pack", file=BytesIO(body + trailer), object_format=self.fmt
        )
        self.addCleanup(data.close)
        index = MemoryPackIndex(
            [(self.base_id, o_base, 0), (b"\x99" * 20, o_delta, 0)],
            self.fmt,
            pack_checksum=trailer,
        )
        pack = Pack.from_objects(data, index)
        self.addCleanup(pack.close)
        with self.assertRaises(ApplyDeltaError):
            bad_type, bad_obj = pack.data.get_object_at(o_delta)
            pack.resolve_object(o_delta, bad_type, bad_obj)
        with self.assertRaises(KeyError):
            pack.data._get_cached_object_at(o_delta)
        with self.assertRaises(KeyError):
            pack.data._get_cached_object_at(o_base)


class ResolveObjectHardeningSHA256Tests(TestCase):
    """The same guarantees must hold for SHA-256 repositories."""

    def setUp(self) -> None:
        super().setUp()
        self.fmt = SHA256
        self.base_data = b"sha256 base"
        self.base_id = _oid(self.fmt, BLOB, self.base_data)
        self.assertEqual(32, len(self.base_id))

    def test_thin_pack_sha256_resolves(self) -> None:
        target = self.base_data + b" extended"
        pack, _, _, _ = build_inmemory_pack(
            self.fmt,
            [
                (
                    REF_DELTA,
                    (self.base_id, _delta(self.base_data, target)),
                    _oid(self.fmt, BLOB, target),
                )
            ],
        )
        self.addCleanup(pack.close)
        pack.resolve_ext_ref = CountingResolver(
            {self.base_id: (BLOB, self.base_data)}
        )
        type_num, raw = pack.get_raw(_oid(self.fmt, BLOB, target))
        self.assertEqual((BLOB, target), (type_num, raw))

    def test_sha256_wrong_hash_is_mismatch(self) -> None:
        target = self.base_data + b" extended"
        pack, _, _, _ = build_inmemory_pack(
            self.fmt,
            [
                (
                    REF_DELTA,
                    (self.base_id, _delta(self.base_data, target)),
                    _oid(self.fmt, BLOB, target),
                )
            ],
        )
        self.addCleanup(pack.close)
        pack.resolve_ext_ref = CountingResolver(
            {self.base_id: (BLOB, b"different sha256 contents")}
        )
        with self.assertRaises(ExternalObjectMismatch) as cm:
            pack.get_raw(_oid(self.fmt, BLOB, target))
        self.assertEqual(32, len(cm.exception.actual_sha))

    def test_sha256_rejects_short_sha1_style_id(self) -> None:
        pack, offsets, _, _ = build_inmemory_pack(
            self.fmt, [(BLOB, self.base_data, self.base_id)]
        )
        self.addCleanup(pack.close)
        with self.assertRaises(InvalidExternalReference):
            pack.resolve_object(
                offsets[0],
                REF_DELTA,
                (b"\xab" * 20, _delta(self.base_data, self.base_data)),
            )

    def test_sha256_external_cycle_without_offset(self) -> None:
        x = sha256(b"x").digest()
        delta = _delta(b"a", b"a")
        pack, offsets, _, _ = build_inmemory_pack(
            self.fmt, [(REF_DELTA, (x, delta), sha256(b"t").digest())]
        )
        self.addCleanup(pack.close)

        def get_ref(sha):
            return None, REF_DELTA, (bytes(sha), delta)

        with self.assertRaises(DeltaCycle):
            pack.resolve_object(
                offsets[0], REF_DELTA, (x, delta), get_ref=get_ref
            )

    def test_sha256_missing_external_is_distinguishable(self) -> None:
        target = self.base_data + b"!"
        pack, _, _, _ = build_inmemory_pack(
            self.fmt,
            [
                (
                    REF_DELTA,
                    (self.base_id, _delta(self.base_data, target)),
                    _oid(self.fmt, BLOB, target),
                )
            ],
        )
        self.addCleanup(pack.close)

        def raising(sha):
            raise KeyError(sha)

        pack.resolve_ext_ref = raising
        with self.assertRaises(ExternalObjectUnavailable):
            pack.get_raw(_oid(self.fmt, BLOB, target))
