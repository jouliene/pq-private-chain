"""Route the two indivisible swap versions. Both legs and their wrapper must agree."""
import swap_wire_a as a
import swap_wire_b as b
from swap_wire_a import BUNDLE, CT_PAIR, FRAME, Frame, HEADER, LEG, LIMIT, MAX_BUNDLE, SIG, require

FRAMES = (a.FRAME, b.FRAME)
BUNDLES = (a.BUNDLE, b.BUNDLE)
LEGS = (a.LEG, b.LEG)


def version(data, tags):
    require(data[:5] in tags, "unknown swap version")
    return b if data.startswith(tags[1]) else a


def leg_shape(leg):
    version(leg, LEGS).leg_shape(leg)


def leg_suite(legs):
    require(len(legs) == 2, "incomplete atomic swap")
    suite = version(legs[0], LEGS)
    require(legs[1].startswith(suite.LEG), "mixed swap versions")
    return suite


def digest(network, terms, expiry, payer, legs):
    return leg_suite(legs).digest(network, terms, expiry, payer, legs)


def assemble(network, terms, expiry, payer, legs, signatures):
    return leg_suite(legs).assemble(network, terms, expiry, payer, legs, signatures)


def read_frame(raw):
    return version(raw, FRAMES).read_frame(raw)


def pair(frames):
    require(len(frames) == 2, "incomplete atomic swap")
    return version(frames[0], FRAMES).pair(frames)


def bundle(frames):
    require(len(frames) == 2, "incomplete atomic swap")
    return version(frames[0], FRAMES).bundle(frames)


def split(raw):
    return version(raw, BUNDLES).split(raw)


def groups(packets):
    stream = iter(packets)
    for first in stream:
        if first.startswith(FRAMES):
            second = next(stream, None)
            require(second is not None, "incomplete atomic swap")
            pair((first, second))
            yield first, second
        else:
            yield (first,)
