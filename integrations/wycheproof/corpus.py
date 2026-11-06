# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0
"""All twelve pinned Wycheproof ML-KEM suites through the existing PVT runner.

Local research only, AS IS. Never edits or packages upstream vectors. The
OpenSSL worker's deterministic randomness interface is strictly for tests.
"""

import hashlib
import json

import re

REVISION = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"
EXTENSION = "co.arteractive.wycheproof"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def typed_hex(value):
    require(isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{2})*", value) is not None,
            "noncanonical upstream hex; stop instead of normalizing")
    return {"kind": "bytes", "value": value, "length": len(value) // 2}

FILES = {
    'mlkem_1024_encaps_test.json': 'da41e8daf57e40a6b334a722e3f56067817352f5583fdb2434da1a2cd611358e',
    'mlkem_1024_keygen_seed_test.json': 'cd9241bf5d65a78e005866ea2c660615c17f50caa9afc2b96fd1573cc65617b5',
    'mlkem_1024_semi_expanded_decaps_test.json': 'a4a7c88152df3d8d4b3f33aad584167dfaff67195cfde08aac4b981030b4d05c',
    'mlkem_1024_test.json': '17c5b764d78c05522f1980fcb41d82add573f11de5d13004ae0b83bf46d9c43a',
    'mlkem_512_encaps_test.json': '85a69664f2e8243f5085f01fb22f9635b100b16a8935cf2b2ac94c127511a20c',
    'mlkem_512_keygen_seed_test.json': '877ae6f5550d0e802086e5812bdbd23c16afa31cd3bff9669cd9661d3fbf2d85',
    'mlkem_512_semi_expanded_decaps_test.json': 'bb90c7997dc3695e52882608b7c79675a012c031dd50dc08e76c4775a762ad14',
    'mlkem_512_test.json': '18bc5455d5bf8226b3ab1d1deb51f3ed7c44b3d90039eb25416d40fa77e76f20',
    'mlkem_768_encaps_test.json': '9d4381f94c40853bba430245b94968b7390d9175aacd9f1ae4e250a71c78b713',
    'mlkem_768_keygen_seed_test.json': 'fde5abe284396f4cb3c4610b90d680f0b57782e94c3365c97aee59e24881ebe4',
    'mlkem_768_semi_expanded_decaps_test.json': 'e4438ab7d4dd7b6ace7165e45aeed4403082f981f86300c8369f69d3d071060a',
    'mlkem_768_test.json': 'c59c067ae794c343df575dd90f6f7458f51881b11a22d6e9d8677c8d9ee21e90',
}
TYPES = {
    'mlkem_test_schema.json': ('MLKEMTest', 'seed-decaps', {'seed': 'seed', 'ciphertext': 'c'},
                             {'shared-secret': 'K', 'public-key': 'ek'}),
    'mlkem_keygen_seed_test_schema.json': ('MLKEMKeyGen', 'keygen', {'seed': 'seed'},
                                         {'public-key': 'ek', 'private-key': 'dk'}),
    'mlkem_encaps_test_schema.json': ('MLKEMEncapsTest', 'encaps', {'public-key': 'ek', 'randomness': 'm'},
                                    {'ciphertext': 'c', 'shared-secret': 'K'}),
    'mlkem_semi_expanded_decaps_test_schema.json': (
        'MLKEMDecapsValidationTest', 'expanded-decaps', {'private-key': 'dk', 'ciphertext': 'c'},
        {'shared-secret': 'K', 'public-key': 'ek'}),
}
BATCH_SIZE = 16


def batches(corpus):
    """Keep the runner's default report/session limits; never omit cases.

    Sixteen cases bound verbose byte mismatches for these pinned ML-KEM
    suites. This is a scoped integration choice, not a general resource proof.
    """
    return [dict(corpus, cases=corpus['cases'][start:start + BATCH_SIZE])
            for start in range(0, len(corpus['cases']), BATCH_SIZE)]


def run_batched(corpus, argv):
    from protocol_vectors.runner import run_adapter
    from protocol_vectors.validation import validate_document
    results = []
    chunks = batches(corpus)
    for chunk in chunks:
        # Source flags/comments may reveal expected rejection. Retain them
        # locally for provenance, but never send them through case_request.
        chunk = dict(chunk, cases=[{k: v for k, v in case.items() if k != 'extensions'}
                                  for case in chunk['cases']])
        require(not validate_document(chunk), 'invalid batch')
        report = run_adapter(chunk, argv)
        # Drop bulky expected/observed byte dumps after counting each batch.
        results.extend({'id': r['id'], 'passed': r['passed']} for r in report['cases'])
    require([r['id'] for r in results] == [c['id'] for c in corpus['cases']],
            'batching lost, duplicated, or reordered a case')
    return {'cases': results, 'batches': len(chunks), 'passed': all(r['passed'] for r in results)}


def convert_file(root, filename):
    raw = (root / 'testvectors_v1' / filename).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == FILES[filename], f'source digest mismatch: {filename}')
    doc = json.loads(raw)
    require(doc['algorithm'] == 'ML-KEM', 'unexpected algorithm')
    group_type, operation, inputs, outputs = TYPES[doc['schema']]
    corpus = {
        'format': 'org.arteractive.protocol-vectors/draft-01',
        'corpus_id': filename.removesuffix('.json').replace('_', '-'),
        'algorithm': {'name': 'ML-KEM Wycheproof integration', 'version': 'FIPS-203',
                      'reference': 'https://csrc.nist.gov/pubs/fips/203/final'},
        'profiles': [], 'encoding': {'byte_strings': 'lowercase-hex',
            'integers': 'canonical-unsigned-decimal', 'default_byte_order': 'little'},
        'provenance': {'artifacts': [{
            'id': 'upstream-source', 'origin': 'external', 'license': 'Apache-2.0',
            'redistribution': 'link-only', 'source_revision': REVISION,
            'source_url': f'https://github.com/C2SP/wycheproof/blob/{REVISION}/testvectors_v1/{filename}',
            'source_sha256': FILES[filename], 'attribution': 'Project Wycheproof contributors',
        }]}, 'cases': [],
        'notes': 'Transient local conversion only. Opaque byte strings; no integer byte-order conversion.',
    }
    ids, profiles = set(), set()
    for group in doc['testGroups']:
        require(group['type'] == group_type, 'unexpected group type')
        parameter = group['parameterSet']
        require(parameter in ('ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'), 'unknown parameter set')
        profile = parameter.lower() + '-' + operation
        if profile not in profiles:
            profiles.add(profile)
            corpus['profiles'].append({'id': profile, 'parameters': {
                'operation': operation, 'parameter-set': parameter}})
        for test in group['tests']:
            require(type(test['tcId']) is int and test['tcId'] not in ids, 'bad/duplicate tcId')
            ids.add(test['tcId'])
            case = {'id': f'{profile}-tc-{test["tcId"]}', 'profile': profile,
                    'inputs': {dest: typed_hex(test[src]) for dest, src in inputs.items()},
                    'extensions': {EXTENSION: {'source-file': filename, 'tcId': test['tcId'],
                        'flags': test.get('flags', []), 'comment': test.get('comment', ''),
                        'group-source': group['source']}}}
            if test['result'] == 'valid':
                case.update(disposition='success', expected_outputs={
                    dest: typed_hex(test[src]) for dest, src in outputs.items()})
            else:
                require(test['result'] == 'invalid', 'unmapped result: do not guess')
                case.update(disposition='expected-error', expected_error={'code': 'mlkem.input-rejected'})
            corpus['cases'].append(case)
    require(len(corpus['cases']) == doc['numberOfTests'], 'source count mismatch')
    return corpus
