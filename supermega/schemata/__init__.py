import json
import jsonschema
import os.path
import urlparse

import errors

class Resolver(jsonschema.RefResolver):
    cache = {}

    def resolve_remote(self, uri):
        schema = self._resolve_local_json(uri)
        # TODO: Does this copy or reference?
        self.store[uri] = schema
        return schema

    @classmethod
    def _resolve_local_json(cls, uri):
        if uri in cls.cache:
            return cls.cache[uri]

        cls.cache[uri] = load(uri)
        jsonschema.Draft3Validator.check_schema(cls.cache[uri])
        return cls.cache[uri]

class Schema(object):
    def __init__(self, name, definition):
        self.name = name
        self.definition = definition
        self._resolver = Resolver.from_schema(definition)

    def validate(self, instance, sub_properties = ()):
        name = self.name
        definition = self.definition

        for prop in sub_properties:
            name += ":{}".format(prop)
            definition = definition['properties'][prop]

        try:
            jsonschema.validate(instance, definition, resolver = self._resolver)
        except jsonschema.ValidationError as e:
            schema = Schema(name, definition)
            raise errors.ValidationError(e, schema, instance)

    @classmethod
    def from_file(cls, schema):
        definition = cls.load_json(schema)
        return cls(schema, definition)

    @staticmethod
    def load_json(json_file):
        # TODO: Move to codec.open
        with open(os.path.join(os.path.dirname(__file__), json_file), 'rb') as f:
                return json.load(f)

OPERATION_SCHEMA = Schema.from_file('operation.json')

def load_bundle(bundle_file, part):
    bundle = Schema.load_json(bundle_file)
    OPERATION_SCHEMA.validate(bundle)
    return (Schema("{}:{}".format(bundle_file, part), bundle[part]['schema']),
        bundle[part]['mapping'])
