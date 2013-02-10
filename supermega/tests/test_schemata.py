import unittest
import copy

from .. import schemata
from .. import errors

TEST_SCHEMA = {
    "type": "object",
    "properties": {
        "t_a_to_b": {"type": "string", "required": True},
        "t_list_of_objects": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "t_object_attribute": {"type": "string", "required": True},
                }
            },
            "required": True
        },
        "t_sub_object": {
            "type": "object",
            "properties": {
                "t_object_attribute": {"type": "string", "required": True}
            }
        }
    }
}

TEST_OPERATION = {
    "schema": TEST_SCHEMA,
    # Translation table
    "mapping": {
        "a_to_b": "t_a_to_b",
        "list_of_objects": ["t_list_of_objects", {
            "object_attribute": "t_object_attribute"
        }],
        "sub_object": ["t_sub_object",{
            "object_attribute": "t_object_attribute"
        }]
    }
}

class TestSchemaBundle(unittest.TestCase):
    def setUp(self):
        self.bundle = schemata.SchemaBundle(
            'test-operation',
            TEST_OPERATION
        )

        self.single_response_bundle = schemata.SchemaBundle(
            'test-single-response',
            {
                "schema": {
                    "type": "string",
                    "required": True
                },
                # Translation table
                "mapping": { "*": "single_response" }
            }
        )

        self.valid_data = {
            "a_to_b": "value of a_to_b",
            "list_of_objects": [{"object_attribute": "object1"},
                {"object_attribute": "object2"}],
            "sub_object": {"object_attribute": "object3"}
        }
        self.invalid_data = copy.deepcopy(self.valid_data)
        del self.invalid_data['a_to_b']
        del self.invalid_data['list_of_objects'][0]['object_attribute']
        # This actually does not raise an error right now, since extraneous
        # items are simply ignored
        self.invalid_data['list_of_objects'][1]['invalid_attribute'] = \
            'value of invalid_attribute'

        self.translated = self.bundle.translate(self.valid_data)

    def test_map_a_to_b(self):
        self.assertEquals(self.translated['t_a_to_b'], 'value of a_to_b')

    def test_map_list_of_objects(self):
        t = self.translated
        print t
        self.assertEquals(len(t['t_list_of_objects']), 2)
        self.assertTrue(isinstance(t['t_list_of_objects'], list))
        self.assertTrue(isinstance(t['t_list_of_objects'][0], dict))
        self.assertTrue(isinstance(t['t_list_of_objects'][1], dict))
        self.assertEquals(t['t_list_of_objects'][0]['t_object_attribute'],
            'object1')
        self.assertEquals(t['t_list_of_objects'][1]['t_object_attribute'],
            'object2')

    def test_map_sub_object(self):
        t = self.translated

        self.assertTrue(isinstance(t['t_sub_object'], dict))
        self.assertEquals(t['t_sub_object']['t_object_attribute'], 'object3')

    def test_map_single_response(self):
        translated = self.single_response_bundle.translate('value')
        self.assertEquals(translated['single_response'], 'value')

    def test_validation(self):
        self.bundle.validate(self.valid_data)
        
        with self.assertRaises(errors.ValidationError):
            self.bundle.validate(self.invalid_data)

    def test_partial_validation(self):
        self.bundle.validate(self.valid_data['list_of_objects'],
            ('list_of_objects',))

        with self.assertRaises(errors.ValidationError):
            self.bundle.validate(self.invalid_data['list_of_objects'],
                ('list_of_objects',))



