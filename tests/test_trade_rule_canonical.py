import pytest

from nth_dao.trade_rules.canonical import (
    MAX_SAFE_INTEGER,
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)


def test_trade_canonical_json_is_sorted_utf8_and_compact():
    value = {"z": "caf\u00e9", "a": {"b": 2, "a": 1}}
    assert trade_canonical_json(value) == (b'{"a":{"a":1,"b":2},"z":"caf\xc3\xa9"}')


@pytest.mark.parametrize(
    "value, reason",
    [
        ({"x": 1.0}, "float"),
        ({"x": MAX_SAFE_INTEGER + 1}, "unsafe integer"),
        ({"x": {1: "bad"}}, "non-string key"),
        ({"x": {"\u00e9": "bad"}}, "non-ASCII key"),
        ({"x": {"": "bad"}}, "invalid ASCII key"),
        ({"x": {"bad key": "bad"}}, "invalid ASCII key"),
        ({"x": "\ud800"}, "invalid Unicode"),
        (["not", "an", "object"], "root"),
    ],
)
def test_trade_canonical_json_rejects_cross_language_ambiguity(value, reason):
    with pytest.raises(TradeCanonicalJSONError, match=reason):
        trade_canonical_json(value)


def test_trade_canonical_json_rejects_cycle():
    value = {}
    value["self"] = value
    with pytest.raises(TradeCanonicalJSONError, match="cyclic"):
        trade_canonical_json(value)


def test_parse_trade_json_rejects_duplicate_keys_before_dict_loss():
    with pytest.raises(TradeCanonicalJSONError, match="duplicate"):
        parse_trade_json('{"a":1,"a":2}')


@pytest.mark.parametrize(
    "raw, reason",
    [
        ('{"x":1.5}', "float"),
        ('{"x":NaN}', "non-finite"),
        (f'{{"x":{MAX_SAFE_INTEGER + 1}}}', "unsafe integer"),
        ("\ufeff{}", "BOM"),
        (b"\xff", "UTF-8"),
        ('{"x":"\\ud800"}', "invalid Unicode"),
        ("[]", "root"),
    ],
)
def test_parse_trade_json_rejects_noncanonical_wire_inputs(raw, reason):
    with pytest.raises(TradeCanonicalJSONError, match=reason):
        parse_trade_json(raw)


def test_safe_integer_boundaries_are_accepted():
    value = {"min": -MAX_SAFE_INTEGER, "max": MAX_SAFE_INTEGER}
    assert parse_trade_json(trade_canonical_json(value)) == value
