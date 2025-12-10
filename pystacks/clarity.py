from .utils import (
    ByteType,
    serialize,
    read_u128_from_stream,
    write_u128_to_stream,
    read_u32_from_stream,
    read_string_from_stream,
    read_ascii_string_from_stream,
    read_vector_u8_from_stream,
)
from io import BytesIO


class TypePrefix(ByteType):

    @serialize(0)
    class Int:
        pass

    @serialize(1)
    class UInt:
        pass

    @serialize(2)
    class Buffer:
        pass

    @serialize(3)
    class BoolTrue:
        pass

    @serialize(4)
    class BoolFalse:
        pass

    @serialize(5)
    class PrincipalStandard:
        pass

    @serialize(6)
    class PrincipalContract:
        pass

    @serialize(7)
    class ResponseOk:
        pass

    @serialize(8)
    class ResponseErr:
        pass

    @serialize(9)
    class OptionalNone:
        pass

    @serialize(10)
    class OptionalSome:
        pass

    @serialize(11)
    class List:
        pass

    @serialize(12)
    class Tuple:
        pass

    @serialize(13)
    class StringASCII:
        pass

    @serialize(14)
    class StringUTF8:
        pass


class Value:

    class Int:
        pass

    class UInt:
        def __init__(self, value):
            self.value = value

        def to_stream(self, stream):
            TypePrefix.UInt().to_stream(stream)
            write_u128_to_stream(stream, self.value)

        @staticmethod
        def from_stream(stream):
            return Value.UInt(read_u128_from_stream(stream))

        def __repr__(self):
            if self.value is not None:
                return "UInt({})".format(self.value)
            raise Exception("Invalid UInt")

    class Bool:
        def __init__(self, boolean=None):
            self.boolean = boolean

        def is_true(self):
            return self.boolean == True

        def is_false(self):
            return self.boolean == False

        def to_stream(self, stream):
            if self.is_true():
                TypePrefix.BoolTrue().to_stream(stream)
                return
            elif self.is_false():
                TypePrefix.BoolFalse().to_stream(stream)
                return
            raise Exception("Invalid Bool")

        def to_bytes(self):
            stream = BytesIO()
            self.to_stream(stream)
            stream.seek(0)
            return stream.read()

        def __repr__(self):
            if self.boolean is True:
                return "True"
            elif self.boolean is False:
                return "False"
            raise Exception("Invalid Bool")

    class Sequence:
        class Buffer:
            pass

        class List:
            def __init__(self, items=None):
                self.items = items

            @staticmethod
            def from_stream(stream):
                _list = Value.Sequence.List()
                _list.items = []
                items_len = read_u32_from_stream(stream)
                for _ in range(0, items_len):
                    value = Value.from_stream(stream)
                    _list.items.append(value)
                return _list

            def __repr__(self):
                output = "List("
                output += ", ".join([repr(value) for value in self.items])
                output += ")"

                return output

        class String:
            class ASCII:
                def __init__(self, _string=None):
                    self._string = _string

                @staticmethod
                def from_stream(stream):
                    _string = Value.Sequence.String.ASCII()
                    _string._string = read_vector_u8_from_stream(stream).decode("ascii")
                    return _string

                def __repr__(self):
                    if self._string is not None:
                        return 'String.ASCII("{}")'.format(self._string)
                    raise Exception("Invalid String.ASCII")

            class UTF8:
                def __init__(self, _string=None):
                    self._string = _string

                @staticmethod
                def from_stream(stream):
                    _string = Value.Sequence.String.ASCII()
                    _string._string = read_vector_u8_from_stream(stream).decode("utf8")
                    return _string

                def __repr__(self):
                    if self._string is not None:
                        return 'String.UTF8("{}")'.format(self._string)
                    raise Exception("Invalid String.UTF8")

    class Principal:
        pass

    class Tuple:
        def __init__(self, items=None):
            self.items = items

        @staticmethod
        def from_stream(stream):
            _tuple = Value.Tuple()
            _tuple.items = []
            items_len = read_u32_from_stream(stream)
            for _ in range(0, items_len):
                key = read_ascii_string_from_stream(stream)
                value = Value.from_stream(stream)
                _tuple.items.append((key, value))
            return _tuple

        def __repr__(self):
            output = "Tuple({"
            output += ", ".join(
                ["{}: {}".format(key, repr(value)) for key, value in self.items]
            )
            output += "})"

            return output

    class Optional:
        def __init__(self, value=None):
            self.value = value

        def is_none(self):
            return self.value is None

        def is_some(self):
            return self.value is not None

        def to_stream(self, stream):
            if self.is_none():
                TypePrefix.OptionalNone().to_stream(stream)
            else:
                TypePrefix.OptionalSome().to_stream(stream)
                self.value.to_stream(stream)

        def to_bytes(self):
            stream = BytesIO()
            self.to_stream(stream)
            stream.seek(0)
            return stream.read()

        def __repr__(self):
            if self.value is not None:
                return "Some({})".format(self.value)
            else:
                return "None"

    class Response:
        def __init__(self, ok=None, err=None):
            self.ok = ok
            self.err = err

        def is_ok(self):
            return self.ok is not None

        def is_err(self):
            return self.err is not None

        def __repr__(self):
            if self.ok is not None:
                return "Ok({})".format(self.ok)
            elif self.err is not None:
                return "Err({})".format(self.err)
            raise Exception("Invalid Result")

    class CallableContract:
        pass

    @staticmethod
    def from_stream(stream):
        type_prefix = TypePrefix.from_stream(stream)
        if isinstance(type_prefix, TypePrefix.Int):
            return Value.Int.from_stream(stream)
        elif isinstance(type_prefix, TypePrefix.UInt):
            return Value.UInt.from_stream(stream)
        elif isinstance(type_prefix, TypePrefix.BoolTrue):
            return Value.Bool(True)
        elif isinstance(type_prefix, TypePrefix.BoolFalse):
            return Value.Bool(False)
        elif isinstance(type_prefix, TypePrefix.OptionalNone):
            return Value.Optional(None)
        elif isinstance(type_prefix, TypePrefix.OptionalSome):
            return Value.Optional(value=Value.from_stream(stream))
        elif isinstance(type_prefix, TypePrefix.ResponseOk):
            return Value.Response(ok=Value.from_stream(stream))
        elif isinstance(type_prefix, TypePrefix.ResponseErr):
            return Value.Response(err=Value.from_stream(stream))
        elif isinstance(type_prefix, TypePrefix.Tuple):
            return Value.Tuple.from_stream(stream)
        elif isinstance(type_prefix, TypePrefix.StringASCII):
            return Value.Sequence.String.ASCII.from_stream(stream)
        elif isinstance(type_prefix, TypePrefix.List):
            return Value.Sequence.List.from_stream(stream)
        else:
            raise Exception("Unsupported TypePrefix: {}".format(type_prefix))

    @staticmethod
    def from_bytes(data):
        stream = BytesIO(data)
        return Value.from_stream(stream)
