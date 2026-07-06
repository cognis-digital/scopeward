from scopeward.reasons import ReasonCode, REASON_DESCRIPTIONS, describe, Decision


def test_every_code_has_a_description():
    for code in ReasonCode:
        assert code.value in REASON_DESCRIPTIONS
        assert REASON_DESCRIPTIONS[code.value]


def test_codes_are_str_comparable():
    assert ReasonCode.ALLOWED == "SW_ALLOWED"
    assert ReasonCode.ALLOWED.value == "SW_ALLOWED"


def test_describe_known_and_unknown():
    assert describe(ReasonCode.REVOKED) == REASON_DESCRIPTIONS["SW_REVOKED"]
    assert describe("SW_REVOKED") == REASON_DESCRIPTIONS["SW_REVOKED"]
    assert describe("SW_MADE_UP") == "Unknown reason code."


def test_decision_bool_and_dict():
    d = Decision(True, ReasonCode.ALLOWED, "ok", {"x": 1})
    assert bool(d) is True
    assert d.to_dict() == {"allowed": True, "code": "SW_ALLOWED", "message": "ok", "detail": {"x": 1}}


def test_all_deny_codes_distinct_from_allow():
    deny = [c for c in ReasonCode if c != ReasonCode.ALLOWED]
    assert len(deny) == len(set(deny))
    assert ReasonCode.ALLOWED not in deny


def test_expected_codes_present():
    expected = {
        "SW_ALLOWED", "SW_SIGNATURE_INVALID", "SW_NOT_SIGNED", "SW_WINDOW_INACTIVE",
        "SW_MODULE_NOT_ALLOWED", "SW_TARGET_UNAUTHORIZED", "SW_DEVICE_UNAUTHORIZED",
        "SW_DESTRUCTIVE_FORBIDDEN", "SW_REVOKED", "SW_EXPIRED", "SW_CAP_NOT_GRANTED",
    }
    assert {c.value for c in ReasonCode} == expected
