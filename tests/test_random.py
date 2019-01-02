import hypothesis.strategies as st
import pytest
from hypothesis import assume, given, settings

from . import common


@pytest.mark.hypothesis
@settings(deadline=250)
@given(
    st.integers(1, 0xFF), st.integers(0, 0xFF), st.binary(min_size=0, max_size=10000)
)
def test_set_get(app, key, data):
    assume(not (app == 0xFF and key == 0xFF))
    # TODO set random reseed?
    sc, sp = common.init(unlock=True)
    app_key = (app << 8) | key
    for s in (sc, sp):
        s.set(app_key, data)
        assert s.get(app_key) == data
    assert sc._dump() == sp._dump()
