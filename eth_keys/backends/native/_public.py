"""Joint secp256k1 multiplication for public signature scalars only."""

from functools import lru_cache

from eth_keys.constants import SECPK1_G as G
from eth_keys.constants import SECPK1_N as N
from eth_keys.constants import SECPK1_P as P

from .jacobian import _add_affine, jacobian_add

# phi(x, y) = (beta*x, y). The lattice columns (a1, b1), (a2, a1)
# satisfy a + lambda*b = 0 mod N, where phi(G) = lambda*G.
_BETA = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
_A1 = 0x3086D221A7D46BCDE86C90E49284EB15
_B1 = -0xE4437ED6010E88286F547FA90ABFE4C3
_A2 = 0x114CA50F7A8E2F3F657C1108D9D44CFD8


def _split(scalar: int) -> tuple[int, int]:
    """Reduce to two signed scalars of at most 129 bits using nearest integers."""
    c1 = (_A1 * scalar + N // 2) // N
    c2 = (-_B1 * scalar + N // 2) // N
    return scalar - c1 * _A1 - c2 * _A2, -c1 * _B1 - c2 * _A1


def _double(point: tuple[int, int, int]) -> tuple[int, int, int]:
    """Double internal canonical points, using secp256k1's zero A coefficient."""
    x, y, z = point
    if not y:
        return (0, 0, 0)
    yy = y * y % P
    s = 4 * x * yy % P
    m = 3 * x * x % P
    nx = (m * m - 2 * s) % P
    return nx, (m * (s - nx) - 8 * yy * yy) % P, 2 * y * z % P


def _odd_multiples(
    point: tuple[int, int], width: int = 5
) -> tuple[tuple[int, int], ...]:
    """Compute the window's odd multiples with one inversion."""
    current = (*point, 1)
    twice = _double(current)
    points = [current]
    for _ in range((1 << (width - 2)) - 1):
        current = jacobian_add(current, twice)
        points.append(current)
    product = 1
    prefixes = []
    for _, _, z in points:
        prefixes.append(product)
        product = product * z % P
    inverse_product = pow(product, -1, P)
    affine = []
    for (x, y, z), prefix in zip(reversed(points), reversed(prefixes), strict=True):
        inverse_z = inverse_product * prefix % P
        inverse_product = inverse_product * z % P
        square = inverse_z * inverse_z % P
        affine.append((x * square % P, y * square * inverse_z % P))
    return tuple(reversed(affine))


@lru_cache(maxsize=1)
def _generator_odds() -> tuple[tuple[tuple[int, int], ...], ...]:
    """Cache only the public width-ten generator and its endomorphism."""
    table = _odd_multiples(G, 10)
    return table, tuple((x * _BETA % P, y) for x, y in table)


def _naf(scalar: int, width: int = 5) -> list[int]:
    """Return signed non-adjacent digits of a public scalar."""
    half = 1 << (width - 1)
    mask = (1 << width) - 1
    digits = []
    while scalar:
        digit = ((scalar + half) & mask) - half if scalar & 1 else 0
        digits.append(digit)
        scalar = (scalar - digit) // 2
    return digits


def _joint_multiply(
    generator_scalar: int, point: tuple[int, int], point_scalar: int
) -> tuple[int, int, int]:
    """Compute u*G + v*P for canonical on-curve points and public scalars < N.

    GLV splits each scalar into two half-size scalars; a shared doubling loop
    combines width-ten generator and width-four variable-point forms. Table indices
    and branches
    depend on public signature/message data. Never call this from signing or
    private-key derivation.
    """
    generator, generator_phi = _generator_odds()
    variable = _odd_multiples(point, 4)
    variable_phi = tuple((x * _BETA % P, y) for x, y in variable)
    first, second = _split(generator_scalar)
    third, fourth = _split(point_scalar)
    digits = (
        _naf(first, 10),
        _naf(second, 10),
        _naf(third, 4),
        _naf(fourth, 4),
    )
    tables = (generator, generator_phi, variable, variable_phi)

    result = (0, 0, 1)
    for bit in range(max(map(len, digits)) - 1, -1, -1):
        result = _double(result)
        for scalar_digits, multiples in zip(digits, tables, strict=True):
            if bit < len(scalar_digits) and (digit := scalar_digits[bit]):
                x, y = multiples[(abs(digit) - 1) // 2]
                result = _add_affine(result, x, y if digit > 0 else -y % P)
    return result
