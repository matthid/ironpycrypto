import sys
config = {'slow_tests': True}
from Crypto import SelfTest
SelfTest.run(verbosity=2, stream=sys.stdout, config=config)