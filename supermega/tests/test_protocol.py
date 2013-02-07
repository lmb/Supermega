import unittest

from .. import protocol
from .. import schemata
from .. import errors

class TestRequest(unittest.TestCase):
    def setUp(self):
        self.req = protocol.Request()
        self.req._schema = schemata.Schema('check-pattern', {
            'type': 'object', 'properties': {
                'test': {
                    'type': 'string',
                    'required': True,
                    'pattern': 'has to match this'
                }
            }
        })

        self.req._mapping = {'test': 'test'}
        self.req.opcode = ''

    def test_assing_invalid_value(self):
        with self.assertRaises(errors.ValidationError):
            self.req['test'] = 'wrong value'

    def test_assign_another_invalid_value(self):
        with self.assertRaises(errors.ValidationError):
            self.req['test'] = {}

    def test_serializing_with_invalid_data(self):
        self.req._data['test'] = 'wrong value again'
        with self.assertRaises(errors.ValidationError):
            self.req.as_serializable_dict()

    def test_assing_valid_value(self):
        # Should not raise
        self.req['test'] = 'has to match this'

    def test_serialize(self):
        self.req.as_serializable_dict()

class TestResponse(unittest.TestCase):
    def setUp(self):
        self.res = protocol.Response()

        # This basically allows all data, provided the root object is a dict
        self.res._schema = schemata.Schema('allow-any', {'type': 'object'})

        self.res._mapping = {
            'to': 'from',
            'to_nested': ('from_nested', {
                'a': '1',
                'b': '2'
            })
        }

    def test_mapping(self):
        self.res.load(None, {
            'from': 'from value',
            'from_nested': {
                '1': 'first value',
                '2': 'second value'
            }
        })

        self.assertEqual(self.res['to'], 'from value')
        self.assertTrue(isinstance(self.res['to_nested'], dict))
        self.assertEqual(self.res['to_nested']['a'], 'first value')
        self.assertEqual(self.res['to_nested']['b'], 'second value')

        self.assertEqual(self.res.as_dict().keys(), self.res._mapping.keys())

if __name__ == '__main__':
    unittest.main()