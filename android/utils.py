import struct

def _reverse_dict(d):
    return dict(map(reversed, d.items()))

def create_struct_funcs(format_, definition):
    struct_format = format_ + ''.join(map(lambda field: field[1], definition))
    keys = list(map(lambda field: field[0], definition))
    mappers = dict(map(lambda field: (field[0], field[2]),
                       filter(lambda field: len(field) > 2, definition)))
    reverse_mappers = dict(map(lambda item: (item[0], _reverse_dict(item[1])),
                               mappers.items()))

    def pack(**kwargs):
        unknown_fields = set(kwargs.keys()) - set(keys)
        missing_fields = set(keys) - set(kwargs.keys())
        if len(unknown_fields) > 0:
            raise TypeError('Unknown field(s): {!r}'.format(unknown_fields))
        if len(missing_fields) > 0:
            raise TypeError('Missing field(s): {!r}'.format(missing_fields))
        for key, mapper in mappers.items():
            kwargs[key] = mapper[kwargs[key]]
        return struct.pack(struct_format, *map(lambda key: kwargs[key], keys))

    def unpack(data):
        result = dict(zip(keys, struct.unpack(struct_format, data)))
        for key, mapper in reverse_mappers.items():
            result[key] = mapper[result[key]]
        return result

    def size():
        return struct.calcsize(struct_format)

    return pack, unpack, size

