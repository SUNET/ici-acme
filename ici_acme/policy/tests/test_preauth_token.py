import os
import unittest

import pkg_resources

from ici_acme.context import Context
from ici_acme.policy.token import is_valid_preauth_token

TOKEN = '''
eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDYXpDQ0FoS2dBd0lCQWdJSU45NDNH
NGpPdEEwd0NnWUlLb1pJemowRUF3SXdJakVUTUJFR0ExVUVBd3dLVFhrZ1VtOXZkQ0JEUVRFTE1Ba0dB
MVVFQmhNQ1UwVXdJQmNOTVRrd05ERXhNVFV5TmpRNVdoZ1BNakV4T1RBek1UZ3hOVEkyTkRsYU1DNHhD
ekFKQmdOVkJBWVRBbE5GTVE0d0RBWURWUVFMREFWVFZVNUZWREVQTUEwR0ExVUVBd3dHWVdSdGFXNHhN
Rmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUV0ZEIyQ3Vha1RnQjI2aWVIVER2SEMrQ0FL
N1VicTdsVHdlb1l1bWo0bnhpMWM3dldYREtVVHB0aTd4QXZDT3d1YkNDb2pJVDRNS1V2ZVF4T0luUGg4
cU9DQVNJd2dnRWVNQjBHQTFVZERnUVdCQlI5RldGamZUQTRybFV2bVRiY0F4WFYwd09mMURBZkJnTlZI
U01FR0RBV2dCUmpPbHllSWpCVGRVT0g1T1hITktaK3BCNnVDREJkQmdnckJnRUZCUWNCQVFSUk1FOHdL
QVlJS3dZQkJRVUhNQUtHSEdoMGRIQTZMeTlqWVM1bGVHRnRjR3hsTG1OdmJTOWpZUzVqY25Rd0l3WUlL
d1lCQlFVSE1BR0dGMmgwZEhBNkx5OXZZM053TG1WNFlXMXdiR1V1WTI5dE1DNEdBMVVkSHdRbk1DVXdJ
NkFob0IrR0hXaDBkSEE2THk5allTNWxlR0Z0Y0d4bExtTnZiUzlqY213dWNHVnRNQ0FHQTFVZEVnUVpN
QmVHRldoMGRIQTZMeTlqWVM1bGVHRnRjR3hsTG1OdmJUQUpCZ05WSFJNRUFqQUFNQXNHQTFVZER3UUVB
d0lGNERBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREFqQUtCZ2dxaGtqT1BRUURBZ05IQURCRUFpQlNt
WGVTQTVBWm9qb24zbklGL1FlaVJvdXVTR1lFWjhIK09JMkVJM21nT2dJZ0Zyc0VTb200THF2ZVllQzNy
RFRia3FLUTB6Y1lwNlJ4ZDV2aFIwWVJFbUk9Il19.eyJuYW1lcyI6WyJ0ZXN0LnRlc3QiXSwibm9uY2U
iOiJocFdHX3hTSmVNUUpqYmpDSF95NV9BIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDAwL25ldy1
hdXRoeiIsImlhdCI6MTU1NTQxMDQ3NCwiZXhwIjoxNTU1NDEwNzc0LCJjcml0IjpbImV4cCJdfQ.dfRq
oOf6OfjzgcPdWm3fLm8t4zlv2oFCSTO1tSmAOgqFU-cj-H3q_Tk3ugfB4ZEvzjXljrwmaMNqH_mmqXIl
nA
'''

# strip newlines
TOKEN=''.join(TOKEN.split('\n'))

class Test_TokenValidation(unittest.TestCase):

    def setUp(self):
        self.data_dir = pkg_resources.resource_filename(__name__, 'data')
        self.ici_ca_dir = os.path.join(self.data_dir, 'ici-ca')
        self.audience = 'http://localhost:8000/new-authz'
        self.context = Context(store=None)
        self.context._nonces['hpWG_xSJeMQJjbjCH_y5_A'] = 'legit'

    def test_token_validate_valid(self):
        res = is_valid_preauth_token(TOKEN, self.ici_ca_dir, self.context, self.audience)
        self.assertEqual(res, ['test.test'])
