#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import unittest
import hashlib
import os

import pyad1.reader
import pyad1.writer


class AD1ReaderTest(unittest.TestCase):

    def test_simple_with_hash_verification(self):
        with pyad1.reader.AD1Reader(os.path.join('test_data', 'text-and-pictures.ad1')) as ad1:
            self.assertEqual(b'C:\\Users\\pcbje\\Desktop\\Data', ad1.logical_image_path)
            self.assertEqual(4, ad1.version)

            for item_type, parent_path, filename, metadata, content in ad1:
                content_digest = hashlib.sha1()
                content_digest.update(content)

                # Normal file.
                if item_type == 0:
                    expected_sha1 = metadata[1][20482].decode('utf-8')
                    actual_sha1 = content_digest.hexdigest()
                    self.assertEqual(expected_sha1, actual_sha1)

if __name__ == '__main__':
    unittest.main()
