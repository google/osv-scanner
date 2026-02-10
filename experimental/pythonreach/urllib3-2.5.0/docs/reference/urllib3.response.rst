Response and Decoders
=====================

Response
--------

.. autoclass:: urllib3.response.BaseHTTPResponse
    :members:
    :undoc-members:
    :show-inheritance:

.. autoclass:: urllib3.response.HTTPResponse
    :members:
    :undoc-members:
    :show-inheritance:
    :inherited-members: json

    .. autoattribute:: auto_close
    .. autoattribute:: status
    .. autoattribute:: headers

Decoders
--------

Decoder classes are used for transforming compressed HTTP bodies
using the ``Content-Encoding`` into their uncompressed binary
representation.

.. autoclass:: urllib3.response.BrotliDecoder
.. autoclass:: urllib3.response.DeflateDecoder
.. autoclass:: urllib3.response.GzipDecoder
.. autoclass:: urllib3.response.ZstdDecoder
.. autoclass:: urllib3.response.MultiDecoder
