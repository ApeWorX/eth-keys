from functools import (
    lru_cache,
)

from eth_keys.constants import (
    IDENTITY_POINTS,
)
from eth_keys.constants import (
    SECPK1_A as A,
)
from eth_keys.constants import (
    SECPK1_G as _G,
)
from eth_keys.constants import (
    SECPK1_N as N,
)
from eth_keys.constants import (
    SECPK1_P as P,
)


def inv(a: int, n: int) -> int:
    if a == 0:
        return 0
    # The general helper historically also accepts noninvertible moduli and
    # subclasses. Keep its original algorithm for those argument forms.
    if type(a) is int and type(n) is int and n in (P, N) and a % n:
        return pow(a, -1, n)
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def to_jacobian(p: tuple[int, int]) -> tuple[int, int, int]:
    o = (p[0], p[1], 1)
    return o


def jacobian_double(p: tuple[int, int, int]) -> tuple[int, int, int]:
    if not p[1]:
        return (0, 0, 0)
    ysq = (p[1] ** 2) % P
    S = (4 * p[0] * ysq) % P
    M = (3 * p[0] ** 2 + A * p[2] ** 4) % P
    nx = (M**2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq**2) % P
    nz = (2 * p[1] * p[2]) % P
    return (nx, ny, nz)


def jacobian_add(
    p: tuple[int, int, int], q: tuple[int, int, int]
) -> tuple[int, int, int]:
    if not p[1]:
        return q
    if not q[1]:
        return p
    U1 = (p[0] * q[2] ** 2) % P
    U2 = (q[0] * p[2] ** 2) % P
    S1 = (p[1] * q[2] ** 3) % P
    S2 = (q[1] * p[2] ** 3) % P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 1)
        return jacobian_double(p)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    nx = (R**2 - H3 - 2 * U1H2) % P
    ny = (R * (U1H2 - nx) - S1 * H3) % P
    nz = (H * p[2] * q[2]) % P
    return (nx, ny, nz)


def from_jacobian(p: tuple[int, int, int]) -> tuple[int, int]:
    z = inv(p[2], P)
    return ((p[0] * z**2) % P, (p[1] * z**3) % P)


def jacobian_multiply(a: tuple[int, int, int], n: int) -> tuple[int, int, int]:
    if a[1] == 0 or n == 0:
        return (0, 0, 1)
    if n == 1:
        return a
    if n < 0 or n >= N:
        return jacobian_multiply(a, n % N)
    if (n % 2) == 0:
        return jacobian_double(jacobian_multiply(a, n // 2))
    elif (n % 2) == 1:
        return jacobian_add(jacobian_double(jacobian_multiply(a, n // 2)), a)
    else:
        raise Exception("Invariant: Unreachable code path")


def fast_multiply(a: tuple[int, int], n: int) -> tuple[int, int]:
    if a is _G and type(n) is int and 1 < n < N:
        return from_jacobian(_multiply_generator(n))
    return from_jacobian(jacobian_multiply(to_jacobian(a), n))


def _add_affine(p: tuple[int, int, int], qx: int, qy: int) -> tuple[int, int, int]:
    """Add a non-identity affine point to a Jacobian accumulator."""
    if not p[1]:
        return (qx, qy, 1)
    x, y, z = p
    z_squared = z * z % P
    u = qx * z_squared % P
    s = qy * z_squared * z % P
    if x == u:
        if y != s:
            return (0, 0, 1)
        return jacobian_double(p)
    h = u - x
    r = s - y
    h_squared = h * h % P
    h_cubed = h * h_squared % P
    x_h_squared = x * h_squared % P
    nx = (r * r - h_cubed - 2 * x_h_squared) % P
    ny = (r * (x_h_squared - nx) - y * h_cubed) % P
    return (nx, ny, h * z % P)


# Each packed coordinate pair occupies 512 bits. Selection divides a complete
# row into halves at these public offsets, independent of the secret scalar.
_COORDINATE_MASK = (1 << 256) - 1
_WINDOW_HALVES = tuple(
    (bit, 512 << bit, (1 << (512 << bit)) - 1) for bit in range(4, -1, -1)
)


@lru_cache(maxsize=1)
def _generator_windows() -> tuple[int, ...]:
    """
    Pack 43 windows of 32 public generator multiples, one inversion per window.

    Row ``i`` holds ``1..32 * 2**(6*i) * G`` in affine coordinates, packed into a
    single integer. Built lazily on first use (about 95 KB).
    """
    windows = []
    base = to_jacobian(_G)
    for _ in range(43):
        points = []
        prefixes = []
        product = 1
        point = base
        for _ in range(32):
            points.append(point)
            prefixes.append(product)
            product = product * point[2] % P
            point = jacobian_add(point, base)
        inverse_product = inv(product, P)
        packed = 0
        for (x, y, z), prefix in zip(reversed(points), reversed(prefixes), strict=True):
            inverse_z = inverse_product * prefix % P
            inverse_product = inverse_product * z % P
            square = inverse_z * inverse_z % P
            affine_x = x * square % P
            affine_y = y * square * inverse_z % P
            packed = (packed << 512) | (affine_y << 256) | affine_x
        windows.append(packed)
        for _ in range(6):
            base = jacobian_double(base)
    return tuple(windows)


def _multiply_generator(n: int) -> tuple[int, int, int]:
    """Multiply G by ``1 < n < N`` with signed six-bit windows."""
    result = (0, 0, 1)
    # Every complete row is read in public order. At each public split read both
    # halves and select with masks, never with a secret index or variable shift.
    # Python integers are variable-time, as in the original bit-test algorithm.
    for packed in _generator_windows():
        digit = ((n + 32) & 63) - 32
        n = (n - digit) >> 6
        negative = digit >> 6
        index = ((digit ^ negative) - negative) - 1
        for bit, shift, mask in _WINDOW_HALVES:
            low = packed & mask
            high = packed >> shift
            packed = low ^ ((low ^ high) & -((index >> bit) & 1))
        x = packed & _COORDINATE_MASK
        y = packed >> 256
        y = ((y ^ negative) - negative) % P
        if digit:
            result = _add_affine(result, x, y)
    return result


def fast_add(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    return from_jacobian(jacobian_add(to_jacobian(a), to_jacobian(b)))


def is_identity(p: tuple[int, int, int]) -> bool:
    return p in IDENTITY_POINTS
