from .utils import ByteType, serialize


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
        pass

    class Bool:
        pass

    class Sequence:
        pass

    class Principal:
        pass

    class Tuple:
        pass

    class Optional:
        def __init__(self):
            self.value = None

        @staticmethod
        def from_stream(stream):
            type_prefix = TypePrefix.from_stream(stream)
            if isinstance(type_prefix, TypePrefix.OptionalNone):
                return Value.Optional()
            elif isinstance(type_prefix, TypePrefix.OptionalSome):
                subtype_prefix = TypePrefix.from_stream(stream)
                return subtype_prefix.from_stream(stream)
            raise Exception("Expected Value.Optional")

    class Response:
        pass

    class CallableContract:
        pass
