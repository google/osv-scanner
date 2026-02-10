Pyodide, Emscripten, and PyScript
=================================

From the Pyodide documentation, `Pyodide <https://pyodide.org>`_ is a Python distribution for the browser and Node.js based on WebAssembly and `Emscripten <https://emscripten.org/>`_.
This technology also underpins the `PyScript framework <https://pyscript.net/>`_ and `Jupyterlite <https://jupyterlite.readthedocs.io/>`_, so should work in those environments too.

Starting in version 2.2.0 urllib3 supports being used in a Pyodide runtime utilizing
the `JavaScript fetch API <https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API>`_
or falling back on `XMLHttpRequest <https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest>`_
if the fetch API isn't available (such as when cross-origin isolation
isn't active). This means you can use Python libraries to make HTTP requests from your browser!

Because urllib3's Emscripten support is API-compatible, this means that
libraries that depend on urllib3 may now be usable from Emscripten and Pyodide environments, too.

 .. warning::

    **Support for Emscripten and Pyodide is experimental**. Report all bugs to the `urllib3 issue tracker <https://github.com/urllib3/urllib3/issues>`_.
    Currently Node.js support is very experimental - see the description below.

It's recommended to `run Pyodide in a Web Worker <https://pyodide.org/en/stable/usage/webworker.html#using-from-webworker>`_
in order to take full advantage of features like the fetch API which enables streaming of HTTP response bodies.

Getting started
---------------

Using urllib3 with Pyodide means you need to `get started with Pyodide first <https://pyodide.org/en/stable/usage/quickstart.html>`_.
The Pyodide project provides a `useful online REPL <https://pyodide.org/en/stable/console.html>`_ to try in your browser without
any setup or installation to test out the code examples below.

One minor note - when running Pyodide code from JavaScript, if you use ``pyodide.runPythonAsync`` rather
than ``pyodide.runPython``, urllib3 can sometimes run more efficiently. It is generally always worth using
``runPythonAsync``.

urllib3's Emscripten support is automatically enabled if ``sys.platform`` is ``"emscripten"``, so no setup is required beyond installation and importing the module.

urllib3 is packaged with the default Pyodide build, so you should be able to use it as normal.

 .. code-block:: python

    import urllib3
    resp = urllib3.request("GET", "https://httpbin.org/anything")

    print(resp.status)  # 200
    print(resp.headers) # HTTPHeaderDict(...)
    print(resp.json())  # {"headers": {"Accept": "*/*", ...}, ...}

Because `Requests <https://requests.readthedocs.io/en/latest/>`_ is built on urllib3, Requests also works out of the box:

 .. code-block:: python

    import requests
    resp = requests.request("GET", "https://httpbin.org/anything")

    print(resp.status_code)  # 200
    print(resp.headers)

Features
--------

Because we use JavaScript APIs under the hood, it's not possible to use all of urllib3 features.
Features which are usable with Emscripten support are:

* Requests over HTTP and HTTPS
* Timeouts
* Retries
* Streaming (with Web Workers and Cross-Origin Isolation)
* Redirects (urllib3 controls redirects in Node.js but not in browsers where behavior is determined by runtime)
* Decompressing response bodies

Features which don't work with Emscripten:

* Proxies, both forwarding and tunneling
* Customizing TLS and certificates (uses browsers' configuration)
* Configuring low-level socket options or source address

Streaming with Web Workers
--------------------------
To access the fetch API and do HTTP response streaming with urllib3
you must be running the code within a Web Worker and set specific HTTP headers
for the serving website to enable `Cross-Origin Isolation <https://developer.mozilla.org/en-US/docs/Web/API/crossOriginIsolated>`_.

You can verify whether a given environment is cross-origin isolated by evaluating the global ``crossOriginIsolated`` JavaScript property.

Node.js support
---------------
Node.js support uses a relatively new feature in WebAssembly known as JavaScript Promise Integration. 
To use urllib3 in Node.js, you need to use Node.js version 20 or newer and may need to call Node.js with
the ``--experimental-wasm-stack-switching`` command line parameter.