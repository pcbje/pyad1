#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import unittest
import sys

if __name__ == '__main__':
    test_suite = unittest.TestLoader().discover('pyad1', pattern='*_test.py')
    test_results = unittest.TextTestRunner(verbosity=2).run(test_suite)
    if not test_results.wasSuccessful():
        sys.exit(1)
