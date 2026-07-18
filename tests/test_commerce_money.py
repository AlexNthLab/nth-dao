from decimal import Decimal

import pytest

from nth_dao.commerce.money import (
    ASSET_DECIMALS,
    MAX_MINOR_AMOUNT,
    MoneyRejected,
    decimal_to_minor,
    minor_to_decimal,
)


def test_exact_minor_conversion():
    assert decimal_to_minor("50.000001", "USDC") == 50_000_001
    assert decimal_to_minor(Decimal("2.5"), "NTH-TEST") == 2_500_000
    assert minor_to_decimal(50_000_001, "USDC") == "50.000001"
    assert minor_to_decimal(2_500_000, "NTH-TEST") == "2.5"


@pytest.mark.parametrize("value", [1.2, "1e2", " 1", "+1", "-1", ".5", "1."])
def test_ambiguous_amounts_are_rejected(value):
    with pytest.raises(MoneyRejected):
        decimal_to_minor(value, "USDC")


def test_precision_and_currency_fail_closed():
    with pytest.raises(MoneyRejected):
        decimal_to_minor("0.0000001", "USDC")
    with pytest.raises(MoneyRejected):
        decimal_to_minor("1.1", "credit")
    with pytest.raises(MoneyRejected):
        decimal_to_minor("1", "USD")


def test_large_decimal_never_rounds_through_decimal_context():
    value = "1234567890123456789012345678.000001"
    with pytest.raises(MoneyRejected, match="range"):
        decimal_to_minor(value, "USDC")


def test_supported_minor_range_is_exact_at_both_edges():
    maximum = "9223372036854.775807"
    assert decimal_to_minor(maximum, "USDC") == MAX_MINOR_AMOUNT
    assert minor_to_decimal(MAX_MINOR_AMOUNT, "USDC") == maximum
    with pytest.raises(MoneyRejected, match="range"):
        decimal_to_minor("9223372036854.775808", "USDC")
    with pytest.raises(MoneyRejected, match="range"):
        minor_to_decimal(MAX_MINOR_AMOUNT + 1, "USDC")


def test_amount_text_and_fractional_precision_are_bounded():
    with pytest.raises(MoneyRejected, match="too long"):
        decimal_to_minor("1" * 97, "USDC")
    with pytest.raises(MoneyRejected, match="fractional digits"):
        decimal_to_minor("1.0000000", "USDC")
    with pytest.raises(MoneyRejected, match="fractional digits"):
        decimal_to_minor("1.0", "credit")


def test_asset_precision_registry_is_immutable():
    with pytest.raises(TypeError):
        ASSET_DECIMALS["USDC"] = 18  # type: ignore[index]
