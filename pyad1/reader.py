#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from operator import itemgetter
import glob
import os
import struct
import zlib
import io
import hashlib


class AD1Reader(object):

    def __init__(self, ad1_path, separator='/', margin=512, string_encoding='utf-8'):
        self.separator = separator
        self.margin = margin
        self.string_encoding = string_encoding

        self.paths = self._Glob(ad1_path)
        self.absolute_offset = 0
        self.header_read = False
        self.sha1_meta_digest = hashlib.sha1()
        self.sha1_content_digest = hashlib.sha1()

    def __enter__(self):
        current_path = self.paths.pop(0)
        self.current_file = open(current_path, 'rb')
        self.current_size = os.path.getsize(current_path)
        self._ReadHeader()
        return self

    def __exit__(self, type, value, traceback):
        self.current_file.close()

    def _ReadHeader(self):
        # Margin.
        self._Read(self.margin, False)

        # Signature.
        self._Read(16)

        # AD1 version (= 3 or 4)
        self.version, = struct.unpack('<I', self._Read(4))

        if self.version != 3 and self.version != 4:
            raise Exception("Invalid version: %s" % self.version)

        # Unknown.
        self._Read(4)

        self.zlib_chunk_size, = struct.unpack("<I", self._Read(4))

        self.image_header_length, = struct.unpack("<q", self._Read(8))

        self.image_header_length_2, = struct.unpack("<q", self._Read(8))

        logical_image_path_length, = struct.unpack('<I', self._Read(4))

        if self.version == 4:
            # Unknown.
            self._Read(44)

        self.logical_image_path = self._Read(logical_image_path_length)

        if self.logical_image_path != 'Custom Content Image([Multi])':
            self._Read(self.margin + self.image_header_length_2 - self.current_file.tell())

        if self.version == 4:
            self._ReadLastFrom(-372)

        self.header_read = True

    def _Glob(self, path):
        if not path.lower().endswith('.ad1'):
            raise ValueError('Invalid path: %s' % path)

        unsorted_ad_paths = glob.glob("%s*" % path[0:-1])

        if len(unsorted_ad_paths) == 0:
            raise Exception('No files found')

        index_ad_paths = []

        for ad_path in unsorted_ad_paths:
            if ad_path.endswith('.txt'):
                continue

            index = int(ad_path.lower().rsplit('.ad', 1)[1])
            index_ad_paths.append((ad_path, index))

        sorted_ad_paths = []

        for ad_path, _ in sorted(index_ad_paths, key=itemgetter(1)):
            sorted_ad_paths.append(ad_path)

        return sorted_ad_paths

    def _Read(self, length, doDigest=True):
        last_read = self.current_file.read(length)
        data = last_read

        while len(data) < length and len(self.paths) > 0:
            if not last_read:
                self.absolute_offset += self.current_file.tell() - self.margin
                self.current_file.close()

                current_path = self.paths.pop(0)
                self.current_size = os.path.getsize(current_path)
                self.current_file = open(current_path, 'rb')
                self.current_file.seek(self.margin)

            last_read = self.current_file.read(length - len(data))
            data += last_read

        if len(data) < length:
            raise Exception('Incomplete read')

        if doDigest:
            self.sha1_meta_digest.update(data)

        return data

    def _ReadLastFrom(self, pos):
        with open(self.paths[-1], 'rb') as inp:
            inp.seek(pos, io.SEEK_END)
            data = inp.read()
            self.sha1_meta_digest.update(data)

    def Sha1Checksum(self):
        return self.sha1_meta_digest.hexdigest()

    def __iter__(self):
        folder_cache = {}

        while len(self.paths) > 0 or self.current_file.tell() < self.current_size - self.margin:
            block_start = self.current_file.tell()

            next_group, next_in_group, next_block, start_of_data, decompressed_size, = struct.unpack('<5q', self._Read(8 * 5))
            item_type, filename_length, = struct.unpack('<2I', self._Read(4 * 2))

            next_block += self.margin
            start_of_data += self.margin

            filename = self._Read(filename_length)
            folder_index, = struct.unpack('<q', self._Read(8))

            parent_path = folder_cache.get(folder_index + self.margin, '')

            if parent_path:
                path = self.separator.join([parent_path, filename.decode(self.string_encoding)])
            else:
                path = filename.decode(self.string_encoding)

            folder_cache[block_start + self.absolute_offset] = path

            content = b''

            if decompressed_size > 0:
                chunk_count = struct.unpack('<q', self._Read(8, False))[0] + 1
                chunk_arr = struct.unpack('<%sq' % chunk_count, self._Read(8 * chunk_count, False))

                for c in range(1, len(chunk_arr)):
                    compressed = self._Read(chunk_arr[c] - chunk_arr[c - 1], False)
                    decompressed = zlib.decompress(compressed)
                    self.sha1_content_digest.update(decompressed)
                    content += decompressed

            metadata = {}

            while next_block > 0:
                next_block, = struct.unpack('<q', self._Read(8))
                category, key, value_length, = struct.unpack('<3I', self._Read(4 * 3))

                if category not in metadata:
                    metadata[category] = {}

                metadata[category][key] = self._Read(value_length)

            yield item_type, parent_path, filename, metadata, content

        self.sha1_meta_digest.update(self.sha1_content_digest.digest())
