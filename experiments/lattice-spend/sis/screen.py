"""Wire cost for the exact response inventory of LLNW Figure 2, at fixed depth."""
import json
from math import comb, factorial


DEPTH = 40
OCCURRENCES = 2
PROOF_CAP = 241_084
NONMEMBERSHIP_BODY = 207_408
SPLIT_ROOM = PROOF_CAP - NONMEMBERSHIP_BODY
GOLDILOCKS = 2**64 - 2**32 + 1


def ceildiv(a, b):
    return -(-a // b)


def width(count):
    """Fixed bit width for the rank of one element of a set of this cardinality."""
    return (count - 1).bit_length()


def repeats(target):
    """Least r with (2/3)^r <= 2^-target; avoid logs at boundaries."""
    r = 0
    while 3**r < 1 << (target+r):
        r += 1
    return r


def opening(n, q, depth, link_randomizer_bits=0):
    if min(n, depth) < 1 or q < 2:
        raise ValueError("invalid LLNW dimensions")
    k = width(q)
    m = 2*n*k
    words = (depth-1)*m + 2*depth*(2*m)
    # Compact, fixed widths: residue bits; exact enumerative rank for binary
    # vectors of fixed weight, and exact rank for uniform permutations.
    all_branches = dict(commitments_bits=3*n*k, revealed_COM_coins_bits=2*m,
                        field_response_bits=words*k, masked_directions_bits=depth)
    case1 = dict(all_branches, permuted_balanced_vectors_bits=2*depth*width(comb(m,m//2)))
    case23 = dict(all_branches, permutation_ranks_bits=2*depth*width(factorial(m)))
    if link_randomizer_bits:
        # One additional binary witness with its own hiding permutation.
        r = link_randomizer_bits
        for branch in [case1,case23]:
            branch["link_mask_bits"] = 2*r*k
        case1["link_balanced_vector_bits"] = width(comb(2*r,r))
        case23["link_permutation_rank_bits"] = width(factorial(2*r))
    return dict(node_bits=n*k,m=m,field_response_words_per_path=words,
                case1=case1,case23=case23,
                case1_B=ceildiv(sum(case1.values()),8),
                case23_B=ceildiv(sum(case23.values()),8))


def pair(row, target, q, link_tags=0):
    r = repeats(target)
    # In the sampled FS transcript the trit vector is recovered through a
    # domain-separated XOF and is absent from the wire. Each party transmits
    # all commitments and its openings; the simulator/model makes no hash edits.
    a,b=row["case1_B"],row["case23_B"]
    return dict(repetitions_per_occurrence=r,
                literal_pair_min_B=2*r*min(a,b)+link_tags,
                literal_pair_max_B=2*r*max(a,b)+link_tags,
                mean_B_numerator=2*r*(a+2*b)+3*link_tags,mean_B_denominator=3,
                tags_B=link_tags,
                raw_response_pair_B=ceildiv(2*r*row["field_response_words_per_path"]*width(q),8),
                interactive_challenge_vector_rank_B_per_path=ceildiv(width(3**r),8))


def data():
    n,q=256,256
    row=opening(n,q,DEPTH)
    link_randomness=4096
    linked=opening(n,q,DEPTH,link_randomness)
    per_link_tag=ceildiv(n*width(q),8)
    # Link uses 256 canonical existing commitment bits and R private random bits.
    max_sum=(256+link_randomness)*(q-1)
    history=dict(n=n,q=q,k=width(q),depth=DEPTH,occurrences=OCCURRENCES,
                 SIS_matrix_raw_B=n*row["m"]*width(q)//8,
                 public_SIS_root_B=ceildiv(n*width(q),8),
                 private_siblings_B_per_path=ceildiv(DEPTH*n*width(q),8),
                 private_directions_B_per_path=ceildiv(DEPTH,8),
                 nodes_hashed_per_new_append=DEPTH,
                 dense_matrix_column_entries_per_path=DEPTH*n*row["m"])
    return dict(split=dict(signed_frame_B=262144,fixed_frame_B=21060,
               proof_cap_B=PROOF_CAP,monetary_model_N=65536,
               monetary_without_paths_B=NONMEMBERSHIP_BODY,room_B=SPLIT_ROOM),
               original_illustration=history,figure2=row,
               two_paths={str(t):pair(row,t,q) for t in (80,128,256,257)},
               same_note_example=dict(random_binary_bits_per_slot=link_randomness,
                 link_tag_B_per_slot=per_link_tag,TCitH_max_integer_dot=max_sum,
                 quotient_bits_per_modular_row=(max_sum//q).bit_length(),
                 TCitH_per_slot_new_random_bit_checks=link_randomness,
                 TCitH_per_slot_modular_rows=n,
                 TCitH_per_slot_quotient_bit_checks=n*(max_sum//q).bit_length(),
                 dot_strictly_below_goldilocks=max_sum<GOLDILOCKS,
                 linked_figure2=linked,linked_pair_at_256=pair(linked,256,q,2*per_link_tag)),
               literal_entropy_floor=dict(
                  smallest_formal_n=1,smallest_formal_q=2,
                  min_all_branches_two_paths_at_256_B=(2*438*199*2)//8,
                  two_paths_floor_at_128_for_injective_256_bit_leaf_B=2*219*199*512//8))


def check(out):
    assert [repeats(t) for t in (80,128,256,257)] == [137,219,438,440]
    for t in (80,128,256,257):
        r=repeats(t)
        assert (2**(r-1)<<t)>3**(r-1) and (2**r<<t)<=3**r
    a=out["figure2"]
    assert a["field_response_words_per_path"]==39*4096+80*8192==815104
    assert a["case1"]["permuted_balanced_vectors_bits"]==80*4090
    assert a["case23"]["permutation_ranks_bits"]==80*43251
    assert out["literal_entropy_floor"]["min_all_branches_two_paths_at_256_B"]>SPLIT_ROOM
    assert a["field_response_words_per_path"]>PROOF_CAP
    assert out["two_paths"]["256"]["raw_response_pair_B"]==714031104
    assert out["same_note_example"]["linked_pair_at_256"]["literal_pair_min_B"]>out["two_paths"]["256"]["literal_pair_min_B"]


if __name__=="__main__":
    result=data()
    check(result)
    print(json.dumps(result,indent=2))
