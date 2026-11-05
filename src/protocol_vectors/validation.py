# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Dependency-free reference validation for the draft-01 interchange format."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .canonical import (
    is_artifact_path,
    is_canonical_decimal,
    is_extension_namespace,
    is_identifier,
    is_lower_hex_bytes,
    is_sha256,
)
from .diagnostics import Diagnostic, ordered

FORMAT_ID = "org.arteractive.protocol-vectors/draft-01"


def validate_document(document: object) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []

    def add(
        code: str,
        path: str,
        message: str,
        *,
        expected: Any = None,
        observed: Any = None,
        case_id: str | None = None,
    ) -> None:
        diagnostics.append(
            Diagnostic(
                code=code,
                path=path,
                message=message,
                expected=expected,
                observed=observed,
                case_id=case_id,
            )
        )

    if not isinstance(document, dict):
        add("PVT0001", "", "document must be a JSON object", expected="object")
        return diagnostics

    _check_keys(
        document,
        "",
        required={"format", "corpus_id", "algorithm", "profiles", "encoding", "provenance", "cases"},
        allowed={"format", "corpus_id", "algorithm", "profiles", "encoding", "provenance", "cases", "extensions", "notes"},
        add=add,
    )

    if document.get("format") != FORMAT_ID:
        add("PVT0004", "/format", "unsupported format identifier", expected=FORMAT_ID, observed=document.get("format"))

    if not is_identifier(document.get("corpus_id")):
        add("PVT0101", "/corpus_id", "corpus_id is not a canonical identifier", observed=document.get("corpus_id"))

    _validate_algorithm(document.get("algorithm"), add)
    profile_ids = _validate_profiles(document.get("profiles"), add)
    default_byte_order = _validate_encoding(document.get("encoding"), add)
    _validate_provenance(document.get("provenance"), add)
    _validate_cases(document.get("cases"), profile_ids, default_byte_order, add)
    if "extensions" in document:
        _validate_extensions(document["extensions"], "/extensions", add)

    notes = document.get("notes")
    if "notes" in document and not isinstance(notes, str):
        add("PVT0002", "/notes", "notes must be a string", expected="string", observed=type(notes).__name__)

    return ordered(diagnostics)


def _check_keys(
    value: Mapping[str, Any],
    path: str,
    *,
    required: set[str],
    allowed: set[str],
    add: Any,
) -> None:
    for key in sorted(required - value.keys()):
        add("PVT0003", _join_pointer(path, key), "required field is missing")
    for key in sorted(value.keys() - allowed):
        add("PVT0005", _join_pointer(path, key), "unknown core field")


def _join_pointer(path: str, token: object) -> str:
    escaped = str(token).replace("~", "~0").replace("/", "~1")
    return f"{path}/{escaped}"


def _validate_algorithm(value: object, add: Any) -> None:
    if not isinstance(value, dict):
        add("PVT0002", "/algorithm", "algorithm must be an object", expected="object")
        return
    _check_keys(value, "/algorithm", required={"name", "version", "reference"}, allowed={"name", "version", "reference"}, add=add)
    for key in ("name", "version"):
        if not isinstance(value.get(key), str) or not value[key]:
            add("PVT0002", f"/algorithm/{key}", f"{key} must be a non-empty string")
    reference = value.get("reference")
    if not isinstance(reference, str) or not reference.startswith("https://"):
        add("PVT0102", "/algorithm/reference", "reference must be an HTTPS URL", observed=reference)


def _validate_profiles(value: object, add: Any) -> set[str]:
    if not isinstance(value, list) or not value:
        add("PVT0002", "/profiles", "profiles must be a non-empty array")
        return set()
    profile_ids: set[str] = set()
    for index, profile in enumerate(value):
        path = f"/profiles/{index}"
        if not isinstance(profile, dict):
            add("PVT0002", path, "profile must be an object")
            continue
        _check_keys(profile, path, required={"id"}, allowed={"id", "description", "parameters", "extensions"}, add=add)
        identifier = profile.get("id")
        if not is_identifier(identifier):
            add("PVT0101", f"{path}/id", "profile id is not canonical", observed=identifier)
        elif identifier in profile_ids:
            add("PVT0103", f"{path}/id", "duplicate profile id", observed=identifier)
        else:
            profile_ids.add(identifier)
        if "description" in profile and not isinstance(profile["description"], str):
            add("PVT0002", f"{path}/description", "description must be a string")
        if "parameters" in profile and not isinstance(profile["parameters"], dict):
            add("PVT0002", f"{path}/parameters", "parameters must be an object")
        if "extensions" in profile:
            _validate_extensions(profile["extensions"], f"{path}/extensions", add)
    return profile_ids


def _validate_encoding(value: object, add: Any) -> str | None:
    if not isinstance(value, dict):
        add("PVT0002", "/encoding", "encoding must be an object")
        return None
    _check_keys(
        value,
        "/encoding",
        required={"byte_strings", "integers", "default_byte_order"},
        allowed={"byte_strings", "integers", "default_byte_order"},
        add=add,
    )
    expected = {
        "byte_strings": "lowercase-hex",
        "integers": "canonical-unsigned-decimal",
    }
    for key, required_value in expected.items():
        if value.get(key) != required_value:
            add("PVT0104", f"/encoding/{key}", "unsupported canonical encoding", expected=required_value, observed=value.get(key))
    if value.get("default_byte_order") not in ("little", "big", "mixed"):
        add("PVT0104", "/encoding/default_byte_order", "unsupported byte order", observed=value.get("default_byte_order"))
        return None
    return value["default_byte_order"]


def _validate_provenance(value: object, add: Any) -> None:
    if not isinstance(value, dict):
        add("PVT0002", "/provenance", "provenance must be an object")
        return
    _check_keys(value, "/provenance", required={"artifacts"}, allowed={"artifacts"}, add=add)
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list):
        add("PVT0002", "/provenance/artifacts", "artifacts must be an array")
        return
    seen: set[str] = set()
    for index, artifact in enumerate(artifacts):
        path = f"/provenance/artifacts/{index}"
        if not isinstance(artifact, dict):
            add("PVT0002", path, "artifact record must be an object")
            continue
        allowed = {
            "id", "origin", "license", "path", "output_sha256", "redistribution",
            "source_url", "source_revision", "source_sha256", "attribution",
            "generator", "transformations",
        }
        _check_keys(artifact, path, required={"id", "origin", "license", "redistribution"}, allowed=allowed, add=add)
        identifier = artifact.get("id")
        if not is_identifier(identifier):
            add("PVT0101", f"{path}/id", "artifact id is not canonical", observed=identifier)
        elif identifier in seen:
            add("PVT0103", f"{path}/id", "duplicate artifact id", observed=identifier)
        else:
            seen.add(identifier)
        origin = artifact.get("origin")
        if origin not in ("original", "generated", "external"):
            add("PVT0201", f"{path}/origin", "unsupported artifact origin", observed=origin)
        if not _is_nonempty_string(artifact.get("license")):
            add("PVT0002", f"{path}/license", "license must be a non-empty SPDX expression or recorded permission")
        redistribution = artifact.get("redistribution")
        if redistribution not in ("original", "permitted", "link-only", "regenerated"):
            add("PVT0203", f"{path}/redistribution", "unsupported redistribution determination", observed=redistribution)
        if redistribution == "link-only":
            for key in ("path", "output_sha256"):
                if key in artifact:
                    add("PVT0204", f"{path}/{key}", "link-only artifact cannot identify redistributed output")
        else:
            for key in ("path", "output_sha256"):
                if key not in artifact:
                    add("PVT0003", f"{path}/{key}", "redistributed artifact field is required")
            if "path" in artifact and not is_artifact_path(artifact.get("path")):
                add("PVT0205", f"{path}/path", "artifact path must be a safe corpus-relative POSIX path", observed=artifact.get("path"))
            if "output_sha256" in artifact and not is_sha256(artifact.get("output_sha256")):
                add("PVT0202", f"{path}/output_sha256", "output_sha256 must be 64 lowercase hexadecimal characters")
        for key in ("source_url", "source_revision", "attribution"):
            if key in artifact and not _is_nonempty_string(artifact.get(key)):
                add("PVT0002", f"{path}/{key}", f"{key} must be a non-empty string")
        if "source_sha256" in artifact and not is_sha256(artifact.get("source_sha256")):
            add("PVT0202", f"{path}/source_sha256", "source_sha256 must be 64 lowercase hexadecimal characters")
        transformations = artifact.get("transformations")
        if "transformations" in artifact and (
            not isinstance(transformations, list)
            or any(not isinstance(item, str) for item in transformations)
        ):
            add("PVT0002", f"{path}/transformations", "transformations must be an array of strings")
        if origin == "external":
            for key in ("source_url", "source_revision", "source_sha256", "attribution"):
                if key not in artifact:
                    add("PVT0003", f"{path}/{key}", "external artifact field is required")
        if origin == "generated":
            if "generator" not in artifact:
                add("PVT0003", f"{path}/generator", "generated artifact requires generator metadata")
            else:
                _validate_generator(artifact.get("generator"), f"{path}/generator", add)
            if "transformations" not in artifact:
                add("PVT0003", f"{path}/transformations", "generated artifact requires explicit transformation history")
        elif "generator" in artifact:
            _validate_generator(artifact.get("generator"), f"{path}/generator", add)


def _validate_generator(value: object, path: str, add: Any) -> None:
    if not isinstance(value, dict):
        add("PVT0002", path, "generator must be an object")
        return
    _check_keys(
        value,
        path,
        required={"name", "version", "argv", "runtime"},
        allowed={"name", "version", "argv", "runtime", "toolchain"},
        add=add,
    )
    for key in ("name", "version", "runtime", "toolchain"):
        if key in value and not _is_nonempty_string(value.get(key)):
            add("PVT0002", f"{path}/{key}", f"{key} must be a non-empty string")
    argv = value.get("argv")
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
        add("PVT0002", f"{path}/argv", "argv must be a non-empty array of strings")


def _is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _validate_cases(
    value: object,
    profile_ids: set[str],
    default_byte_order: str | None,
    add: Any,
) -> None:
    if not isinstance(value, list) or not value:
        add("PVT0002", "/cases", "cases must be a non-empty array")
        return
    seen: set[str] = set()
    for index, case in enumerate(value):
        path = f"/cases/{index}"
        if not isinstance(case, dict):
            add("PVT0002", path, "case must be an object")
            continue
        allowed = {"id", "profile", "disposition", "inputs", "deterministic_choices", "expected_outputs", "expected_error", "extensions", "notes"}
        _check_keys(case, path, required={"id", "profile", "disposition", "inputs"}, allowed=allowed, add=add)
        case_id = case.get("id") if isinstance(case.get("id"), str) else None
        if not is_identifier(case.get("id")):
            add("PVT0101", f"{path}/id", "case id is not canonical", observed=case.get("id"))
        elif case["id"] in seen:
            add("PVT0103", f"{path}/id", "duplicate case id", observed=case["id"], case_id=case_id)
        else:
            seen.add(case["id"])
        if not isinstance(case.get("profile"), str) or case["profile"] not in profile_ids:
            add("PVT0301", f"{path}/profile", "case references an unknown profile", observed=case.get("profile"), case_id=case_id)
        disposition = case.get("disposition")
        if disposition not in ("success", "expected-error", "total-decoding"):
            add("PVT0302", f"{path}/disposition", "unsupported case disposition", observed=disposition, case_id=case_id)
        _validate_value_map(case.get("inputs"), f"{path}/inputs", default_byte_order, add, case_id)
        if "deterministic_choices" in case:
            _validate_value_map(case.get("deterministic_choices"), f"{path}/deterministic_choices", default_byte_order, add, case_id)
        if disposition in ("success", "total-decoding"):
            if "expected_outputs" not in case:
                add("PVT0003", f"{path}/expected_outputs", "successful case requires expected_outputs", case_id=case_id)
            else:
                _validate_value_map(case.get("expected_outputs"), f"{path}/expected_outputs", default_byte_order, add, case_id)
            if "expected_error" in case:
                add("PVT0303", f"{path}/expected_error", "successful case cannot declare expected_error", case_id=case_id)
        elif disposition == "expected-error":
            error = case.get("expected_error")
            if not isinstance(error, dict):
                add("PVT0304", f"{path}/expected_error", "expected-error case requires a non-empty error code", case_id=case_id)
            else:
                _check_keys(error, f"{path}/expected_error", required={"code"}, allowed={"code"}, add=add)
                if not _is_nonempty_string(error.get("code")):
                    add("PVT0304", f"{path}/expected_error/code", "expected error code must be a non-empty string", case_id=case_id)
            if "expected_outputs" in case:
                add("PVT0303", f"{path}/expected_outputs", "expected-error case cannot declare expected_outputs", case_id=case_id)
        if "notes" in case and not isinstance(case.get("notes"), str):
            add("PVT0002", f"{path}/notes", "notes must be a string", case_id=case_id)
        if "extensions" in case:
            _validate_extensions(case["extensions"], f"{path}/extensions", add)


def _validate_value_map(
    value: object,
    path: str,
    default_byte_order: str | None,
    add: Any,
    case_id: str | None,
) -> None:
    if not isinstance(value, dict):
        add("PVT0002", path, "value collection must be an object", case_id=case_id)
        return
    for name, item in sorted(value.items()):
        item_path = _join_pointer(path, name)
        if not is_identifier(name):
            add("PVT0101", item_path, "field name is not a canonical identifier", observed=name, case_id=case_id)
        if not isinstance(item, dict):
            add("PVT0002", item_path, "encoded value must be an object", case_id=case_id)
            continue
        kind = item.get("kind")
        if kind == "bytes":
            _check_keys(item, item_path, required={"kind", "value", "length"}, allowed={"kind", "value", "length", "byte_order"}, add=add)
            encoded = item.get("value")
            length = item.get("length")
            if not is_lower_hex_bytes(encoded):
                add("PVT0401", f"{item_path}/value", "bytes must use even-length lowercase hexadecimal", observed=encoded, case_id=case_id)
            if not isinstance(length, int) or isinstance(length, bool) or length < 0:
                add("PVT0402", f"{item_path}/length", "byte length must be a non-negative integer", observed=length, case_id=case_id)
            elif is_lower_hex_bytes(encoded) and len(encoded) // 2 != length:
                add("PVT0403", f"{item_path}/length", "declared byte length does not match encoded value", expected=len(encoded) // 2, observed=length, case_id=case_id)
            if "byte_order" in item and item["byte_order"] not in ("little", "big"):
                add("PVT0104", f"{item_path}/byte_order", "unsupported byte order", observed=item["byte_order"], case_id=case_id)
            if default_byte_order == "mixed" and "byte_order" not in item:
                add("PVT0104", f"{item_path}/byte_order", "mixed corpus requires byte_order on every bytes value", case_id=case_id)
        elif kind == "integer":
            _check_keys(item, item_path, required={"kind", "value"}, allowed={"kind", "value"}, add=add)
            if not is_canonical_decimal(item.get("value")):
                add("PVT0404", f"{item_path}/value", "integer must use canonical unsigned decimal", observed=item.get("value"), case_id=case_id)
        else:
            add("PVT0405", f"{item_path}/kind", "unsupported encoded value kind", observed=kind, case_id=case_id)


def _validate_extensions(value: object, path: str, add: Any) -> None:
    if not isinstance(value, dict):
        add("PVT0002", path, "extensions must be an object")
        return
    for key in sorted(value):
        if not is_extension_namespace(key):
            add("PVT0501", _join_pointer(path, key), "extension key must be an HTTPS URI or reverse-DNS namespace", observed=key)
