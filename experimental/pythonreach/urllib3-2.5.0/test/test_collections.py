from __future__ import annotations

import typing

import pytest

from urllib3._collections import HTTPHeaderDict
from urllib3._collections import RecentlyUsedContainer as Container


class TestLRUContainer:
    def test_maxsize(self) -> None:
        d: Container[int, str] = Container(5)

        for i in range(5):
            d[i] = str(i)

        assert len(d) == 5

        for i in range(5):
            assert d[i] == str(i)

        d[i + 1] = str(i + 1)

        assert len(d) == 5
        assert 0 not in d
        assert (i + 1) in d

    def test_maxsize_0(self) -> None:
        d: Container[int, int] = Container(0)
        d[1] = 1
        assert len(d) == 0

    def test_expire(self) -> None:
        d: Container[int, str] = Container(5)

        for i in range(5):
            d[i] = str(i)

        for i in range(5):
            d.get(0)

        # Add one more entry
        d[5] = "5"

        # Check state
        assert list(d._container.keys()) == [2, 3, 4, 0, 5]

    def test_same_key(self) -> None:
        d: Container[str, int] = Container(5)

        for i in range(10):
            d["foo"] = i

        assert list(d._container.keys()) == ["foo"]
        assert len(d) == 1

    def test_access_ordering(self) -> None:
        d: Container[int, bool] = Container(5)

        for i in range(10):
            d[i] = True

        # Keys should be ordered by access time
        assert list(d._container.keys()) == [5, 6, 7, 8, 9]

        new_order = [7, 8, 6, 9, 5]
        for k in new_order:
            d[k]

        assert list(d._container.keys()) == new_order

    def test_delete(self) -> None:
        d: Container[int, bool] = Container(5)

        for i in range(5):
            d[i] = True

        del d[0]
        assert 0 not in d

        d.pop(1)
        assert 1 not in d

        d.pop(1, None)

    def test_get(self) -> None:
        d: Container[int, bool | int] = Container(5)

        for i in range(5):
            d[i] = True

        r = d.get(4)
        assert r is True

        r = d.get(5)
        assert r is None

        r = d.get(5, 42)
        assert r == 42

        with pytest.raises(KeyError):
            d[5]

    def test_disposal(self) -> None:
        evicted_items: list[int] = []

        def dispose_func(arg: int) -> None:
            # Save the evicted datum for inspection
            evicted_items.append(arg)

        d: Container[int, int] = Container(5, dispose_func=dispose_func)
        for i in range(5):
            d[i] = i
        assert list(d._container.keys()) == list(range(5))
        assert evicted_items == []  # Nothing disposed

        d[5] = 5
        assert list(d._container.keys()) == list(range(1, 6))
        assert evicted_items == [0]

        del d[1]
        assert evicted_items == [0, 1]

        d.clear()
        assert evicted_items == [0, 1, 2, 3, 4, 5]

    def test_iter(self) -> None:
        d: Container[str, str] = Container()

        with pytest.raises(NotImplementedError):
            d.__iter__()


class NonMappingHeaderContainer:
    def __init__(self, **kwargs: str) -> None:
        self._data = {}
        self._data.update(kwargs)

    def keys(self) -> typing.Iterator[str]:
        return iter(self._data)

    def __getitem__(self, key: str) -> str:
        return self._data[key]


@pytest.fixture()
def d() -> HTTPHeaderDict:
    header_dict = HTTPHeaderDict(Cookie="foo")
    header_dict.add("cookie", "bar")
    return header_dict


class TestHTTPHeaderDict:
    def test_create_from_kwargs(self) -> None:
        h = HTTPHeaderDict(ab="1", cd="2", ef="3", gh="4")
        assert len(h) == 4
        assert "ab" in h

    def test_setdefault(self) -> None:
        h = HTTPHeaderDict(a="1")
        assert h.setdefault("A", "3") == "1"
        assert h.setdefault("b", "2") == "2"
        assert h.setdefault("c") == ""
        assert h["c"] == ""
        assert h["b"] == "2"

    def test_create_from_dict(self) -> None:
        h = HTTPHeaderDict(dict(ab="1", cd="2", ef="3", gh="4"))
        assert len(h) == 4
        assert "ab" in h

    def test_create_from_iterator(self) -> None:
        teststr = "urllib3ontherocks"
        h = HTTPHeaderDict((c, c * 5) for c in teststr)
        assert len(h) == len(set(teststr))

    def test_create_from_list(self) -> None:
        headers = [
            ("ab", "A"),
            ("cd", "B"),
            ("cookie", "C"),
            ("cookie", "D"),
            ("cookie", "E"),
        ]
        h = HTTPHeaderDict(headers)
        assert len(h) == 3
        assert "ab" in h
        clist = h.getlist("cookie")
        assert len(clist) == 3
        assert clist[0] == "C"
        assert clist[-1] == "E"

    def test_create_from_headerdict(self) -> None:
        headers = [
            ("ab", "A"),
            ("cd", "B"),
            ("cookie", "C"),
            ("cookie", "D"),
            ("cookie", "E"),
        ]
        org = HTTPHeaderDict(headers)
        h = HTTPHeaderDict(org)
        assert len(h) == 3
        assert "ab" in h
        clist = h.getlist("cookie")
        assert len(clist) == 3
        assert clist[0] == "C"
        assert clist[-1] == "E"
        assert h is not org
        assert h == org

    def test_setitem(self, d: HTTPHeaderDict) -> None:
        d["Cookie"] = "foo"
        # The bytes value gets converted to str. The API is typed for str only,
        # but the implementation continues supports bytes.
        d[b"Cookie"] = "bar"  # type: ignore[index]
        assert d["cookie"] == "bar"
        d["cookie"] = "with, comma"
        assert d.getlist("cookie") == ["with, comma"]

    def test_update(self, d: HTTPHeaderDict) -> None:
        d.update(dict(Cookie="foo"))
        assert d["cookie"] == "foo"
        d.update(dict(cookie="with, comma"))
        assert d.getlist("cookie") == ["with, comma"]

    def test_delitem(self, d: HTTPHeaderDict) -> None:
        del d["cookie"]
        assert "cookie" not in d
        assert "COOKIE" not in d

    def test_add_well_known_multiheader(self, d: HTTPHeaderDict) -> None:
        d.add("COOKIE", "asdf")
        assert d.getlist("cookie") == ["foo", "bar", "asdf"]
        assert d["cookie"] == "foo, bar, asdf"

    def test_add_comma_separated_multiheader(self, d: HTTPHeaderDict) -> None:
        d.add("bar", "foo")
        # The bytes value gets converted to str. The API is typed for str only,
        # but the implementation continues supports bytes.
        d.add(b"BAR", "bar")  # type: ignore[arg-type]
        d.add("Bar", "asdf")
        assert d.getlist("bar") == ["foo", "bar", "asdf"]
        assert d["bar"] == "foo, bar, asdf"

    def test_extend_from_list(self, d: HTTPHeaderDict) -> None:
        d.extend([("set-cookie", "100"), ("set-cookie", "200"), ("set-cookie", "300")])
        assert d["set-cookie"] == "100, 200, 300"

    def test_extend_from_dict(self, d: HTTPHeaderDict) -> None:
        d.extend(dict(cookie="asdf"), b="100")
        assert d["cookie"] == "foo, bar, asdf"
        assert d["b"] == "100"
        d.add("cookie", "with, comma")
        assert d.getlist("cookie") == ["foo", "bar", "asdf", "with, comma"]

    def test_extend_from_container(self, d: HTTPHeaderDict) -> None:
        h = NonMappingHeaderContainer(Cookie="foo", e="foofoo")
        d.extend(h)
        assert d["cookie"] == "foo, bar, foo"
        assert d["e"] == "foofoo"
        assert len(d) == 2

    def test_header_repeat(self, d: HTTPHeaderDict) -> None:
        d["other-header"] = "hello"
        d.add("other-header", "world")

        assert list(d.items()) == [
            ("Cookie", "foo"),
            ("Cookie", "bar"),
            ("other-header", "hello"),
            ("other-header", "world"),
        ]

        d.add("other-header", "!", combine=True)
        expected_results = [
            ("Cookie", "foo"),
            ("Cookie", "bar"),
            ("other-header", "hello"),
            ("other-header", "world, !"),
        ]

        assert list(d.items()) == expected_results
        # make sure the values persist over copies
        assert list(d.copy().items()) == expected_results

        other_dict = HTTPHeaderDict()
        # we also need for extensions to properly maintain results
        other_dict.extend(d)
        assert list(other_dict.items()) == expected_results

    def test_extend_from_headerdict(self, d: HTTPHeaderDict) -> None:
        h = HTTPHeaderDict(Cookie="foo", e="foofoo")
        d.extend(h)
        assert d["cookie"] == "foo, bar, foo"
        assert d["e"] == "foofoo"
        assert len(d) == 2

    @pytest.mark.parametrize("args", [(1, 2), (1, 2, 3, 4, 5)])
    def test_extend_with_wrong_number_of_args_is_typeerror(
        self, d: HTTPHeaderDict, args: tuple[int, ...]
    ) -> None:
        with pytest.raises(
            TypeError, match=r"extend\(\) takes at most 1 positional arguments"
        ):
            d.extend(*args)  # type: ignore[arg-type]

    def test_copy(self, d: HTTPHeaderDict) -> None:
        h = d.copy()
        assert d is not h
        assert d == h

    def test_getlist(self, d: HTTPHeaderDict) -> None:
        assert d.getlist("cookie") == ["foo", "bar"]
        assert d.getlist("Cookie") == ["foo", "bar"]
        assert d.getlist("b") == []
        d.add("b", "asdf")
        assert d.getlist("b") == ["asdf"]

    def test_getlist_after_copy(self, d: HTTPHeaderDict) -> None:
        assert d.getlist("cookie") == HTTPHeaderDict(d).getlist("cookie")

    def test_equal(self, d: HTTPHeaderDict) -> None:
        b = HTTPHeaderDict(cookie="foo, bar")
        c = NonMappingHeaderContainer(cookie="foo, bar")
        e = [("cookie", "foo, bar")]
        assert d == b
        assert d == c
        assert d == e
        assert d != 2

    def test_not_equal(self, d: HTTPHeaderDict) -> None:
        b = HTTPHeaderDict(cookie="foo, bar")
        c = NonMappingHeaderContainer(cookie="foo, bar")
        e = [("cookie", "foo, bar")]
        assert not (d != b)
        assert not (d != c)
        assert not (d != e)
        assert d != 2

    def test_pop(self, d: HTTPHeaderDict) -> None:
        key = "Cookie"
        a = d[key]
        b = d.pop(key)
        assert a == b
        assert key not in d
        with pytest.raises(KeyError):
            d.pop(key)
        dummy = object()
        assert dummy is d.pop(key, dummy)

    def test_discard(self, d: HTTPHeaderDict) -> None:
        d.discard("cookie")
        assert "cookie" not in d
        d.discard("cookie")

    def test_len(self, d: HTTPHeaderDict) -> None:
        assert len(d) == 1
        d.add("cookie", "bla")
        d.add("asdf", "foo")
        # len determined by unique fieldnames
        assert len(d) == 2

    def test_repr(self, d: HTTPHeaderDict) -> None:
        rep = "HTTPHeaderDict({'Cookie': 'foo, bar'})"
        assert repr(d) == rep

    def test_items(self, d: HTTPHeaderDict) -> None:
        items = d.items()
        assert len(items) == 2
        assert list(items) == [
            ("Cookie", "foo"),
            ("Cookie", "bar"),
        ]
        assert ("Cookie", "foo") in items
        assert ("Cookie", "bar") in items
        assert ("X-Some-Header", "foo") not in items
        assert ("Cookie", "not_present") not in items
        assert ("Cookie", 1) not in items  # type: ignore[comparison-overlap]
        assert "Cookie" not in items  # type: ignore[comparison-overlap]

    def test_dict_conversion(self, d: HTTPHeaderDict) -> None:
        # Also tested in connectionpool, needs to preserve case
        hdict = {
            "Content-Length": "0",
            "Content-type": "text/plain",
            "Server": "Hypercorn/1.2.3",
        }
        h = dict(HTTPHeaderDict(hdict).items())
        assert hdict == h
        assert hdict == dict(HTTPHeaderDict(hdict))

    def test_string_enforcement(self, d: HTTPHeaderDict) -> None:
        # This currently throws AttributeError on key.lower(), should
        # probably be something nicer
        with pytest.raises(Exception):
            d[3] = "5"  # type: ignore[index]
        with pytest.raises(Exception):
            d.add(3, "4")  # type: ignore[arg-type]
        with pytest.raises(Exception):
            del d[3]  # type: ignore[arg-type]
        with pytest.raises(Exception):
            HTTPHeaderDict({3: 3})  # type: ignore[arg-type]

    def test_dunder_contains(self, d: HTTPHeaderDict) -> None:
        """
        Test:

        HTTPHeaderDict.__contains__ returns True
          - for matched string objects
          - for case-similar string objects
        HTTPHeaderDict.__contains__ returns False
          - for non-similar strings
          - for non-strings, even if they are keys
            in the underlying datastructure
        """
        assert "cookie" in d
        assert "CoOkIe" in d
        assert "Not a cookie" not in d

        marker = object()
        d._container[marker] = ["some", "strings"]  # type: ignore[index]
        assert marker not in d
        assert marker in d._container

    def test_union(self, d: HTTPHeaderDict) -> None:
        to_merge = {"Cookie": "tim-tam"}
        result = d | to_merge
        assert result == HTTPHeaderDict({"Cookie": "foo, bar, tim-tam"})
        assert to_merge == {"Cookie": "tim-tam"}
        assert d == HTTPHeaderDict({"Cookie": "foo, bar"})

    def test_union_rhs(self, d: HTTPHeaderDict) -> None:
        to_merge = {"Cookie": "tim-tam"}
        result = to_merge | d
        assert result == HTTPHeaderDict({"Cookie": "tim-tam, foo, bar"})
        assert to_merge == {"Cookie": "tim-tam"}
        assert d == HTTPHeaderDict({"Cookie": "foo, bar"})

    def test_inplace_union(self, d: HTTPHeaderDict) -> None:
        to_merge = {"Cookie": "tim-tam"}
        d |= to_merge
        assert d == HTTPHeaderDict({"Cookie": "foo, bar, tim-tam"})

    def test_union_with_unsupported_type(self, d: HTTPHeaderDict) -> None:
        with pytest.raises(TypeError, match="unsupported operand type.*'int'"):
            d | 42
        with pytest.raises(TypeError, match="unsupported operand type.*'float'"):
            3.14 | d

    def test_inplace_union_with_unsupported_type(self, d: HTTPHeaderDict) -> None:
        with pytest.raises(TypeError, match="unsupported operand type.*'NoneType'"):
            d |= None
