import unittest
from pystacks.clarity import Value


class TestClarity(unittest.TestCase):

    def test_value_optional_is_none(self):
        self.assertTrue(Value.Optional(None).is_none())

    def test_value_optional_is_some(self):
        self.assertTrue(Value.Optional(Value.UInt(1)).is_some())

    def test_value_optional_none_serialized(self):
        self.assertEqual(Value.Optional(None).to_bytes(), b"\x09")

    def test_value_bool_false_serialized(self):
        self.assertEqual(Value.Bool(False).to_bytes(), b"\x04")

    def test_value_bool_true_serialized(self):
        self.assertEqual(Value.Bool(True).to_bytes(), b"\x03")

    def test_value_string_utf8_serialized(self):
        self.assertEqual(
            Value.Sequence.String.UTF8("test").to_bytes(), b"\x0e\x00\x00\x00\x04test"
        )
