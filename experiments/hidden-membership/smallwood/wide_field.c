/* GF(2^256) modulo X^256+X^10+X^5+X^2+1. Local calibration, not constant time. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

typedef struct { uint64_t limb[4]; } elt;
static inline void product_xor(elt *out, const elt *a, const elt *b) {
    uint64_t t[8] = {0};
    for (unsigned i=0; i<4; i++)
        for (unsigned j=0; j<4; j++) {
            __m128i q = _mm_clmulepi64_si128(_mm_set_epi64x(0,a->limb[i]),
                                             _mm_set_epi64x(0,b->limb[j]),0);
            t[i+j] ^= (uint64_t)_mm_cvtsi128_si64(q);
            t[i+j+1] ^= (uint64_t)_mm_extract_epi64(q,1);
        }
    for (int i=7; i>=4; --i) {
        uint64_t v=t[i];
        t[i-4] ^= v ^ (v<<2) ^ (v<<5) ^ (v<<10);
        t[i-3] ^= (v>>62) ^ (v>>59) ^ (v>>54);
    }
    for (unsigned j=0;j<4;j++) out->limb[j] ^= t[j];
}

static PyObject *field_mul(PyObject *self, PyObject *args) {
    PyObject *x, *y;
    elt a,b,c={{0}};
    if (!PyArg_ParseTuple(args,"OO",&x,&y)) return NULL;
    PyObject *xx=PyNumber_Index(x), *yy=PyNumber_Index(y);
    if (!xx || !yy) { Py_XDECREF(xx); Py_XDECREF(yy); return NULL; }
    int err=_PyLong_AsByteArray((PyLongObject*)xx,(unsigned char*)&a,sizeof(a),1,0) ||
            _PyLong_AsByteArray((PyLongObject*)yy,(unsigned char*)&b,sizeof(b),1,0);
    Py_DECREF(xx); Py_DECREF(yy);
    if (err) return NULL;
    product_xor(&c,&a,&b);
    return _PyLong_FromByteArray((unsigned char*)&c,sizeof(c),1,0);
}

/* A rows of coefficients times a B-row transpose; little-endian fixed-width field elements. */
static PyObject *matrix_product(PyObject *self, PyObject *args) {
    const char *a,*b;
    Py_ssize_t na,nb,width;
    if (!PyArg_ParseTuple(args,"y#y#n",&a,&na,&b,&nb,&width)) return NULL;
    if (width<=0 || width>PY_SSIZE_T_MAX/32 || na%(width*32) || nb%(width*32)) {
        PyErr_SetString(PyExc_ValueError,"matrix dimensions");
        return NULL;
    }
    const Py_ssize_t rows=na/(width*32), cols=nb/(width*32);
    if (cols && rows>PY_SSIZE_T_MAX/32/cols) return PyErr_NoMemory();
    PyObject *obj=PyBytes_FromStringAndSize(NULL,rows*cols*32);
    if (!obj) return NULL;
    char *dest=PyBytes_AS_STRING(obj);
    Py_BEGIN_ALLOW_THREADS
    for (Py_ssize_t j=0;j<cols;j++)
        for (Py_ssize_t i=0;i<rows;i++) {
            elt r={{0}};
            for (Py_ssize_t k=0;k<width;k++) {
                elt x,y;
                memcpy(&x,a+32*(i*width+k),32);
                memcpy(&y,b+32*(j*width+k),32);
                product_xor(&r,&x,&y);
            }
            memcpy(dest+32*(j*rows+i),&r,32);
        }
    Py_END_ALLOW_THREADS
    return obj;
}

static PyMethodDef methods[]={
    {"mul",field_mul,METH_VARARGS,NULL},{"matrix_product",matrix_product,METH_VARARGS,NULL},
    {NULL,NULL,0,NULL}
};
static struct PyModuleDef mod={PyModuleDef_HEAD_INIT,"sw_wide",NULL,-1,methods};
PyMODINIT_FUNC PyInit_sw_wide(void) { return PyModule_Create(&mod); }
