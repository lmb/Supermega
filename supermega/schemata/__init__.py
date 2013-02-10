import json
import jsonschema
import os.path
import urlparse

from .. import errors

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

        cls.cache[uri] = Schema.load_json(uri)
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

class SchemaBundle(object):
    OPERATION_SCHEMA = Schema.from_file('operation.json')
    BUNDLE_SCHEMA = Schema.from_file('bundle.json')

    def __init__(self, name, operation, validate = True):
        if validate:
            self.OPERATION_SCHEMA.validate(operation)

        self.mapping = operation['mapping']
        if isinstance(self.mapping, basestring):
            self.mapping = {self.mapping: None}

        self.schema = Schema(name, operation['schema'])

    @classmethod
    def from_file(cls, bundle_file, part):
        bundle = Schema.load_json(bundle_file)
        cls.BUNDLE_SCHEMA.validate(bundle)
        return cls("{}:{}".format(bundle_file, part), bundle[part], False)

    def validate(self, instance, sub_properties = ()):
        translated_sub_properties = []
        mapping = self.mapping

        for prop in sub_properties:
            if isinstance(mapping[prop], list):
                translated_sub_properties.append(mapping[prop][0])
                mapping = mapping[prop][1]
            else:
                translated_sub_properties.append(mapping[prop])
                mapping = None
                break

        if mapping:
            translated_instance = []
            if isinstance(instance, list):
                for entry in instance:
                    translated_instance.append(self._translate(entry, mapping))
                instance = translated_instance
            else:
                instance = self._translate(instance, mapping)

        self.schema.validate(instance, translated_sub_properties)


    def translate(self, data, sub_properties = ()):
        mapping = self.mapping
        for prop in sub_properties:
            if isinstance(mapping[prop], list):
                mapping = mapping[prop][1]
            else:
                return data

        return self._translate(data, mapping)

    def _translate(self, data, mapping):
        container = {}
        for attr_from, attr_to in mapping.iteritems():
            if attr_from == '*':
                container[attr_to] = data

            # TODO: Nested mapping can not be optional. Should they be?
            elif isinstance(attr_to, (list, tuple)):
                # Map nested attributes
                nested_mapping = attr_to[1]
                attr_to = attr_to[0]

                if isinstance(data[attr_from], list):
                    # Map a list of objects
                    container[attr_to] = []
                    for entry in data[attr_from]:
                        obj = self._translate(entry, nested_mapping)
                        container[attr_to].append(obj)
                else:
                    # Map an object
                    container[attr_to] = self._translate(data[attr_from],
                        nested_mapping)

            elif attr_from in data:
                # Map a -> b
                container[attr_to] = data[attr_from]

        return container

