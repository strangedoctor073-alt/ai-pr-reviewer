from lib.core.parser import parse


def test_parse():
    assert parse("{}") == {}
