User Guide
==========

.. currentmodule:: urllib3

Installing
----------

urllib3 can be installed with `pip <https://pip.pypa.io>`_

.. code-block:: bash

  $ python -m pip install urllib3


Making Requests
---------------

First things first, import the urllib3 module:

.. code-block:: python

    import urllib3

You'll need a :class:`~poolmanager.PoolManager` instance to make requests.
This object handles all of the details of connection pooling and thread safety
so that you don't have to:

.. code-block:: python

    http = urllib3.PoolManager()

To make a request use :meth:`~urllib3.PoolManager.request`:

.. code-block:: python

    import urllib3

    # Creating a PoolManager instance for sending requests.
    http = urllib3.PoolManager()

    # Sending a GET request and getting back response as HTTPResponse object.
    resp = http.request("GET", "https://httpbin.org/robots.txt")

    # Print the returned data.
    print(resp.data)
    # b"User-agent: *\nDisallow: /deny\n"

``request()`` returns a :class:`~response.HTTPResponse` object, the
:ref:`response_content` section explains how to handle various responses.

You can use :meth:`~urllib3.PoolManager.request` to make requests using any
HTTP verb:

.. code-block:: python

    import urllib3

    http = urllib3.PoolManager()
    resp = http.request(
        "POST",
        "https://httpbin.org/post",
        fields={"hello": "world"} #  Add custom form fields
    )

    print(resp.data)
    # b"{\n "form": {\n "hello": "world"\n  }, ... }

The :ref:`request_data` section covers sending other kinds of requests data,
including JSON, files, and binary data.

.. note:: For quick scripts and experiments you can also use a top-level ``urllib3.request()``.
    It uses a module-global ``PoolManager`` instance.
    Because of that, its side effects could be shared across dependencies relying on it.
    To avoid side effects, create a new ``PoolManager`` instance and use it instead.
    In addition, the method does not accept the low-level ``**urlopen_kw`` keyword arguments.
    System CA certificates are loaded on default.

.. _response_content:

Response Content
----------------

The :class:`~response.HTTPResponse` object provides
:attr:`~response.HTTPResponse.status`, :attr:`~response.HTTPResponse.data`, and
:attr:`~response.HTTPResponse.headers` attributes:

.. code-block:: python

    import urllib3

    # Making the request (The request function returns HTTPResponse object)
    resp = urllib3.request("GET", "https://httpbin.org/ip")

    print(resp.status)
    # 200
    print(resp.data)
    # b"{\n  "origin": "104.232.115.37"\n}\n"
    print(resp.headers)
    # HTTPHeaderDict({"Content-Length": "32", ...})

.. _json_content:

JSON Content
~~~~~~~~~~~~
JSON content can be loaded by :meth:`~response.HTTPResponse.json` 
method of the response:

.. code-block:: python

    import urllib3

    resp = urllib3.request("GET", "https://httpbin.org/ip")

    print(resp.json())
    # {"origin": "127.0.0.1"}

Alternatively, Custom JSON libraries such as `orjson` can be used to encode data,
retrieve data by decoding and deserializing the :attr:`~response.HTTPResponse.data` 
attribute of the request:

.. code-block:: python

    import orjson
    import urllib3

    encoded_data = orjson.dumps({"attribute": "value"})
    resp = urllib3.request(method="POST", url="http://httpbin.org/post", body=encoded_data)

    print(orjson.loads(resp.data)["json"])
    # {'attribute': 'value'}

Binary Content
~~~~~~~~~~~~~~

The :attr:`~response.HTTPResponse.data` attribute of the response is always set
to a byte string representing the response content:

.. code-block:: python

    import urllib3

    resp = urllib3.request("GET", "https://httpbin.org/bytes/8")

    print(resp.data)
    # b"\xaa\xa5H?\x95\xe9\x9b\x11"

.. note:: For larger responses, it's sometimes better to :ref:`stream <stream>`
    the response.

Using io Wrappers with Response Content
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes you want to use :class:`io.TextIOWrapper` or similar objects like a CSV reader
directly with :class:`~response.HTTPResponse` data. Making these two interfaces play nice
together requires using the :attr:`~response.HTTPResponse.auto_close` attribute by setting it
to ``False``. By default HTTP responses are closed after reading all bytes, this disables that behavior:

.. code-block:: python

    import io
    import urllib3

    resp = urllib3.request("GET", "https://example.com", preload_content=False)
    resp.auto_close = False

    for line in io.TextIOWrapper(resp):
        print(line)
    # <!doctype html>
    # <html>
    # <head>
    # ....
    # </body>
    # </html>

.. _request_data:

Request Data
------------

Headers
~~~~~~~

You can specify headers as a dictionary in the ``headers`` argument in :meth:`~urllib3.PoolManager.request`:

.. code-block:: python

    import urllib3

    resp = urllib3.request(
        "GET",
        "https://httpbin.org/headers",
        headers={
            "X-Something": "value"
        }
    )

    print(resp.json()["headers"])
    # {"X-Something": "value", ...}

Or you can use the ``HTTPHeaderDict`` class to create multi-valued HTTP headers:

.. code-block:: python

    import urllib3

    # Create an HTTPHeaderDict and add headers
    headers = urllib3.HTTPHeaderDict()
    headers.add("Accept", "application/json")
    headers.add("Accept", "text/plain")

    # Make the request using the headers
    resp = urllib3.request(
        "GET",
        "https://httpbin.org/headers",
        headers=headers
    )

    print(resp.json()["headers"])
    # {"Accept": "application/json, text/plain", ...}

Cookies
~~~~~~~

Cookies are specified using the ``Cookie`` header with a string containing
the ``;`` delimited key-value pairs:

.. code-block:: python

    import urllib3

    resp = urllib3.request(
        "GET",
        "https://httpbin.org/cookies",
        headers={
            "Cookie": "session=f3efe9db; id=30"
        }
    )

    print(resp.json())
    # {"cookies": {"id": "30", "session": "f3efe9db"}}  

Note that the ``Cookie`` header will be stripped if the server redirects to a
different host.

Cookies provided by the server are stored in the ``Set-Cookie`` header:

.. code-block:: python

    import urllib3

    resp = urllib3.request(
        "GET",
        "https://httpbin.org/cookies/set/session/f3efe9db",
        redirect=False
    )

    print(resp.headers["Set-Cookie"])
    # session=f3efe9db; Path=/

Query Parameters
~~~~~~~~~~~~~~~~

For ``GET``, ``HEAD``, and ``DELETE`` requests, you can simply pass the
arguments as a dictionary in the ``fields`` argument to
:meth:`~urllib3.PoolManager.request`:

.. code-block:: python

    import urllib3

    resp = urllib3.request(
        "GET",
        "https://httpbin.org/get",
        fields={"arg": "value"}
    )

    print(resp.json()["args"])
    # {"arg": "value"}

For ``POST`` and ``PUT`` requests, you need to manually encode query parameters
in the URL:

.. code-block:: python

    from urllib.parse import urlencode
    import urllib3

    # Encode the args into url grammar.
    encoded_args = urlencode({"arg": "value"})

    # Create a URL with args encoded.
    url = "https://httpbin.org/post?" + encoded_args
    resp = urllib3.request("POST", url)

    print(resp.json()["args"])
    # {"arg": "value"}


.. _form_data:

Form Data
~~~~~~~~~

For ``PUT`` and ``POST`` requests, urllib3 will automatically form-encode the
dictionary in the ``fields`` argument provided to
:meth:`~urllib3.PoolManager.request`:

.. code-block:: python

    import urllib3

    resp = urllib3.request(
        "POST",
        "https://httpbin.org/post",
        fields={"field": "value"}
    )
    
    print(resp.json()["form"])
    # {"field": "value"}

.. _json:

JSON
~~~~

To send JSON in the body of a request, provide the data in the ``json`` argument to 
:meth:`~urllib3.PoolManager.request` and  urllib3 will automatically encode the data
using the ``json`` module with ``UTF-8`` encoding. 
In addition, when ``json`` is provided, the ``"Content-Type"`` in headers is set to 
``"application/json"`` if not specified otherwise.

.. code-block:: python

    import urllib3

    resp = urllib3.request(
        "POST",
        "https://httpbin.org/post",
        json={"attribute": "value"},
        headers={"Content-Type": "application/json"}
    )

    print(resp.json())
    # {'headers': {'Content-Type': 'application/json', ...}, 
    #  'data': '{"attribute":"value"}', 'json': {'attribute': 'value'}, ...}
    
Files & Binary Data
~~~~~~~~~~~~~~~~~~~

For uploading files using ``multipart/form-data`` encoding you can use the same
approach as :ref:`form_data` and specify the file field as a tuple of
``(file_name, file_data)``:

.. code-block:: python

    import urllib3

    # Reading the text file from local storage.
    with open("example.txt") as fp:
        file_data = fp.read()
    
    # Sending the request.
    resp = urllib3.request(
        "POST",
        "https://httpbin.org/post",
        fields={
           "filefield": ("example.txt", file_data),
        }
    )
    
    print(resp.json()["files"])
    # {"filefield": "..."}

While specifying the filename is not strictly required, it's recommended in
order to match browser behavior. You can also pass a third item in the tuple
to specify the file's MIME type explicitly:

.. code-block:: python

    resp = urllib3.request(
        "POST",
        "https://httpbin.org/post",
        fields={
            "filefield": ("example.txt", file_data, "text/plain"),
        }
    )

For sending raw binary data simply specify the ``body`` argument. It's also
recommended to set the ``Content-Type`` header:

.. code-block:: python

    import urllib3

    with open("/home/samad/example.jpg", "rb") as fp:
        binary_data = fp.read()

    resp = urllib3.request(
        "POST",
        "https://httpbin.org/post",
        body=binary_data,
        headers={"Content-Type": "image/jpeg"}
    )

    print(resp.json()["data"])
    # data:application/octet-stream;base64,...

.. _ssl:

Certificate Verification
------------------------

.. note:: *New in version 1.25:*

    HTTPS connections are now verified by default (``cert_reqs = "CERT_REQUIRED"``).

While you can disable certification verification by setting ``cert_reqs = "CERT_NONE"``, it is highly recommend to leave it on.

Unless otherwise specified urllib3 will try to load the default system certificate stores.
The most reliable cross-platform method is to use the `certifi <https://certifi.io/>`_
package which provides Mozilla's root certificate bundle:

.. code-block:: bash

    $ python -m pip install certifi

Once you have certificates, you can create a :class:`~poolmanager.PoolManager`
that verifies certificates when making requests:

.. code-block:: python

    import certifi
    import urllib3

    http = urllib3.PoolManager(
        cert_reqs="CERT_REQUIRED",
        ca_certs=certifi.where()
    )

The :class:`~poolmanager.PoolManager` will automatically handle certificate
verification and will raise :class:`~exceptions.SSLError` if verification fails:

.. code-block:: python

    import certifi
    import urllib3

    http = urllib3.PoolManager(
        cert_reqs="CERT_REQUIRED",
        ca_certs=certifi.where()
    )

    http.request("GET", "https://httpbin.org/")
    # (No exception)

    http.request("GET", "https://expired.badssl.com")
    # urllib3.exceptions.SSLError ...

.. note:: You can use OS-provided certificates if desired. Just specify the full
    path to the certificate bundle as the ``ca_certs`` argument instead of
    ``certifi.where()``. For example, most Linux systems store the certificates
    at ``/etc/ssl/certs/ca-certificates.crt``. Other operating systems can
    be `difficult <https://stackoverflow.com/questions/10095676/openssl-reasonable-default-for-trusted-ca-certificates>`_.

Using Timeouts
--------------

Timeouts allow you to control how long (in seconds) requests are allowed to run
before being aborted. In simple cases, you can specify a timeout as a ``float``
to :meth:`~urllib3.PoolManager.request`:

.. code-block:: python

    import urllib3

    resp = urllib3.request(
        "GET",
        "https://httpbin.org/delay/3",
        timeout=4.0
    )

    print(type(resp))
    # <class "urllib3.response.HTTPResponse">

    # This request will take more time to process than timeout.
    urllib3.request(
        "GET",
        "https://httpbin.org/delay/3",
        timeout=2.5
    )
    # MaxRetryError caused by ReadTimeoutError

For more granular control you can use a :class:`~util.timeout.Timeout`
instance which lets you specify separate connect and read timeouts:

.. code-block:: python

    import urllib3

    resp = urllib3.request(
        "GET",
        "https://httpbin.org/delay/3",
        timeout=urllib3.Timeout(connect=1.0)
    )

    print(type(resp))
    # <urllib3.response.HTTPResponse>

    urllib3.request(
        "GET",
        "https://httpbin.org/delay/3",
        timeout=urllib3.Timeout(connect=1.0, read=2.0)
    )
    # MaxRetryError caused by ReadTimeoutError


If you want all requests to be subject to the same timeout, you can specify
the timeout at the :class:`~urllib3.poolmanager.PoolManager` level:

.. code-block:: python

    import urllib3

    http = urllib3.PoolManager(timeout=3.0)
    
    http = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=1.0, read=2.0)
    )

You still override this pool-level timeout by specifying ``timeout`` to
:meth:`~urllib3.PoolManager.request`.

Retrying Requests
-----------------

urllib3 can automatically retry idempotent requests. This same mechanism also
handles redirects. You can control the retries using the ``retries`` parameter
to :meth:`~urllib3.PoolManager.request`. By default, urllib3 will retry
requests 3 times and follow up to 3 redirects.

To change the number of retries just specify an integer:

.. code-block:: python

    import urllib3

    urllib3.request("GET", "https://httpbin.org/ip", retries=10)

To disable all retry and redirect logic specify ``retries=False``:

.. code-block:: python

    import urllib3

    urllib3.request(
        "GET",
        "https://nxdomain.example.com",
        retries=False
    )
    # NewConnectionError

    resp = urllib3.request(
        "GET",
        "https://httpbin.org/redirect/1",
        retries=False
    )

    print(resp.status)
    # 302

To disable redirects but keep the retrying logic, specify ``redirect=False``:

.. code-block:: python

    resp = urllib3.request(
        "GET",
        "https://httpbin.org/redirect/1",
        redirect=False
    )
    
    print(resp.status)
    # 302

For more granular control you can use a :class:`~util.retry.Retry` instance.
This class allows you far greater control of how requests are retried.

For example, to do a total of 3 retries, but limit to only 2 redirects:

.. code-block:: python

    urllib3.request(
        "GET",
        "https://httpbin.org/redirect/3",
        retries=urllib3.Retry(3, redirect=2)
    )
    # MaxRetryError

You can also disable exceptions for too many redirects and just return the
``302`` response:

.. code-block:: python

    resp = urllib3.request(
        "GET",
        "https://httpbin.org/redirect/3",
        retries=urllib3.Retry(
            redirect=2,
            raise_on_redirect=False
        )
    )
    
    print(resp.status)
    # 302

If you want all requests to be subject to the same retry policy, you can
specify the retry at the :class:`~urllib3.poolmanager.PoolManager` level:

.. code-block:: python

    import urllib3

    http = urllib3.PoolManager(retries=False)

    http = urllib3.PoolManager(
        retries=urllib3.Retry(5, redirect=2)
    )

You still override this pool-level retry policy by specifying ``retries`` to
:meth:`~urllib3.PoolManager.request`.

Errors & Exceptions
-------------------

urllib3 wraps lower-level exceptions, for example:

.. code-block:: python

    import urllib3

    try:
        urllib3.request("GET","https://nx.example.com", retries=False)

    except urllib3.exceptions.NewConnectionError:
        print("Connection failed.")
    # Connection failed.

See :mod:`~urllib3.exceptions` for the full list of all exceptions.

Logging
-------

If you are using the standard library :mod:`logging` module urllib3 will
emit several logs. In some cases this can be undesirable. You can use the
standard logger interface to change the log level for urllib3's logger:

.. code-block:: python

    logging.getLogger("urllib3").setLevel(logging.WARNING)
