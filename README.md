pyad1
================

A Python library for parsing AccessData AD1 forensic images (FTK Imager).
This is a work in progress, please use with caution.

### Installation

```bash
git clone https://github.com/pcbje/pyad1
cd pyad1
python setup.py install
python run_tests.py
```

### Usage

```python
# python demo.py some-image.ad1 ./output
import sys
import os

import pyad1.reader

with pyad1.reader.AD1Reader(sys.argv[1]) as ad1:
    for item_type, folder, filename, metadata, content in ad1:
        output_folder = os.path.join(sys.argv[2], folder)

        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        if item_type == 0:
            with open(os.path.join(output_folder, filename), 'wb') as out:
                out.write(content)
            # ...
```

### Todo

* Format documentation
* Hash verification
* Image creation
* Encrypted images
