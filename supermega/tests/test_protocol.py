import unittest

from .. import protocol
from .. import schemata
from .. import errors

class TestOperation(unittest.TestCase):
    class DummyOperation(protocol.Operation):
        schema = '../tests/dummy-operation.bundle.json'

    def setUp(self):
        self.op = self.DummyOperation()

    def test_assign_invalid_value(self):
        with self.assertRaises(errors.ValidationError):
            self.op['pattern'] = 'wrong value'

    def test_assign_another_invalid_value(self):
        with self.assertRaises(errors.ValidationError):
            self.op['pattern'] = {}

        with self.assertRaises(errors.ValidationError):
            self.op['int'] = 'not an int'

    def test_serializing_with_invalid_data(self):
        self.op._request_data['pattern'] = 'wrong value again'
        self.op._request_data['int'] = {}

        with self.assertRaises(errors.ValidationError):
            self.op.get_serializable_request()

    def test_assing_valid_value(self):
        self.op['pattern'] = 'has to match this'
        self.op['int'] = 42

        self.op.get_serializable_request()

    def test_response_mapping(self):
        self.op.load_response({
            'from': 'from value',
            'from_nested': {
                '1': 'first value',
                '2': 'second value'
            }
        })

        res = self.op.response()

        self.assertEqual(res['to'], 'from value')
        self.assertTrue(isinstance(res['to_nested'], dict))
        self.assertEqual(res['to_nested']['a'], 'first value')
        self.assertEqual(res['to_nested']['b'], 'second value')

if __name__ == '__main__':
    unittest.main()