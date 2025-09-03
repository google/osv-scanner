/*
Copyright (c) 2016, PyData Development Team
All rights reserved.

Distributed under the terms of the BSD Simplified License.

The full license is in the LICENSE file, distributed with this software.
*/

#include "pandas/parser/io.h"

/*
  On-disk FILE, uncompressed
*/

void *new_rd_source(PyObject *obj) {
  rd_source *rds = (rd_source *)malloc(sizeof(rd_source));

  if (rds == NULL) {
    PyErr_NoMemory();
    return NULL;
  }
  /* hold on to this object */
  Py_INCREF(obj);
  rds->obj = obj;
  rds->buffer = NULL;
  rds->position = 0;

  return (void *)rds;
}

/*

  Cleanup callbacks

 */

void del_rd_source(void *rds) {
  Py_XDECREF(RDS(rds)->obj);
  Py_XDECREF(RDS(rds)->buffer);
  free(rds);
}

/*

  IO callbacks

 */

char *buffer_rd_bytes(void *source, size_t nbytes, size_t *bytes_read,
                      int *status, const char *encoding_errors) {
  rd_source *src = RDS(source);
  PyGILState_STATE state = PyGILState_Ensure();

  /* delete old object */
  Py_XDECREF(src->buffer);
  src->buffer = NULL;
  PyObject *args = Py_BuildValue("(i)", nbytes);

  PyObject *func = PyObject_GetAttrString(src->obj, "read");

  /* Note: PyObject_CallObject requires the GIL */
  PyObject *result = PyObject_CallObject(func, args);
  Py_XDECREF(args);
  Py_XDECREF(func);

  if (result == NULL) {
    PyGILState_Release(state);
    *bytes_read = 0;
    *status = CALLING_READ_FAILED;
    return NULL;
  } else if (!PyBytes_Check(result)) {
    PyObject *tmp = PyUnicode_AsEncodedString(result, "utf-8", encoding_errors);
    Py_DECREF(result);
    if (tmp == NULL) {
      PyGILState_Release(state);
      return NULL;
    }
    result = tmp;
  }

  const size_t length = PySequence_Length(result);

  if (length == 0)
    *status = REACHED_EOF;
  else
    *status = 0;

  /* hang on to the Python object */
  src->buffer = result;
  char *retval = PyBytes_AsString(result);

  PyGILState_Release(state);

  /* TODO: more error handling */
  *bytes_read = length;

  return retval;
}
