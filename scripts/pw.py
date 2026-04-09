"""
Run

```
python -m sage.doctest pw.py
```

- P :: A list of probabilities describing a distribution
- S :: The password distribution
- S_{¬x} :: Output y given x ::  y ← S / {x}
- T :: Output y s.t. x ← S; y ← S_{-x}

"""

from sage.all import GeneralDiscreteDistribution, randint, RR


class Dist(GeneralDiscreteDistribution):
    def __init__(self, P, seed=None):
        self.P = P
        self.seed = seed
        GeneralDiscreteDistribution.__init__(self, P=P, seed=seed)

    def negx(self, x, seed=None):
        """
        Return S_{¬x}

        :param x: An element in S

        EXAMPLE ::

            sage: P = [0.1, 0.2, 0.3, 0.4]
            sage: S = Dist(P, seed=1312)
            sage: trials = 2^16

            sage: S0 = S.negx(0, seed=1337)
            sage: L0 = [S0.get_random_element() for _ in range(trials)]
            sage: R0 = [S.get_random_element_negx(0) for _ in range(trials)]
            sage: [round(trials*p) for p in S0.P]
            [0, 14564, 21845, 29127]
            sage: [L0.count(i) for i in range(4)]
            [0, 14518, 21700, 29318]
            sage: [R0.count(i) for i in range(4)]
            [0, 14509, 22000, 29027]

            sage: S2 = S.negx(2, seed=1337)
            sage: L2 = [S2.get_random_element() for _ in range(trials)]
            sage: R2 = [S.get_random_element_negx(2) for _ in range(trials)]
            sage: [round(trials*p) for p in S2.P]
            [9362, 18725, 0, 37449]
            sage: [L2.count(i) for i in range(4)]
            [9365, 18572, 0, 37599]
            sage: [R2.count(i) for i in range(4)]
            [9260, 18723, 0, 37553]

        """
        T = [0.0 for _ in range(len(self.P))]
        P_ = [p for p in self.P]
        P_[x] = 0
        P_ = Dist.normalize(P_)
        for i in range(len(self.P)):
            if i == x:
                continue
            T[i] += P_[i]
        T = Dist.normalize(T)
        return Dist(tuple(T), seed=seed)

    def get_random_element_negx(self, x):
        """
        Sample from S_{¬x}.

        :param x: An element in S
        """

        while True:
            y = self.get_random_element()
            if y != x:
                return y

    def T(self, seed=None):
        """
        Return T

        EXAMPLE ::

            sage: P = [0.1, 0.2, 0.3, 0.4]
            sage: S = Dist(P, seed=1312)
            sage: trials = 2^16

            sage: T = S.T(seed=1337)
            sage: L = [T.get_random_element() for _ in range(trials)]
            sage: R = [S.get_random_element_t() for _ in range(trials)]
            sage: [round(trials*p) for p in T.P]
            [8816, 15812, 20207, 20701]
            sage: [L.count(i) for i in range(4)]
            [8845, 15708, 20038, 20945]
            sage: [R.count(i) for i in range(4)]
            [8767, 15677, 20476, 20616]

        """
        T = [0.0 for _ in range(len(self.P))]
        for i in range(len(self.P)):
            P_ = [p for p in self.P]
            P_[i] = 0
            P_ = Dist.normalize(P_)
            for j in range(len(self.P)):
                T[j] += self.P[i] * P_[j]
        T = Dist.normalize(T)
        return Dist(T, seed)

    def get_random_element_t(self):
        """
        Sample from T.
        """
        x = self.get_random_element()
        return self.get_random_element_negx(x)

    @classmethod
    def normalize(cls, P):
        """
        Enforce that the probabilities sum to 1.

        :param P: A list of probabilities describing a distribution

        EXAMPLE ::

            sage: Dist.normalize([0.1, 0.4])
            (0.200000000000000, 0.800000000000000)

        """

        s = sum(P)
        return tuple([p / s for p in P])

    def most_likely_element(self):
        """
        Return an element with highest likelihood.

        """

        return self.P.index(max(self.P))


def advf(S, x):
    """
    The optimal adversary against our game.

    :param S: A distribution.
    :param x: A candidate element.

    """
    T = S.T()
    V = S.negx(x)

    b_ = bool(S.P[x] > T.P[x])
    x_ = V.most_likely_element()

    return b_, x_


def advf_bad_S(S, x):
    """
    A bad adversary that guesses from S instead of S_{¬x}

    :param S: A distribution.
    :param x: A candidate element.

    """
    T = S.T()

    b_ = bool(S.P[x] >= T.P[x])
    x_ = S.most_likely_element()

    return b_, x_


def advf_bad_real(S, x):
    """
    The 'abductor' adversary which will use the `x` it was given if it believes it to be real.

    :param S: A distribution.
    :param x: A candidate element.

    """
    T = S.T()
    V = S.negx(x)

    b_ = bool(S.P[x] >= T.P[x])
    if b_ == 1:
        x_ = x
    else:
        x_ = V.most_likely_element()

    return b_, x_


def advf_trivial(_, x):
    """
    This adversary motivates the `b == 0` check in the conjunction.

    :param S: A distribution.
    :param x: A candidate element.

    """

    # real game: b=0 ⇒ win, b=1 ⇒ lose
    # No b==0: b=0 ⇒ win, b=1 ⇒ win

    b_ = 0
    x_ = x
    return b_, x_


def game(P, adv, seed=None):
    S = Dist(P, seed=seed)
    x = [0, 0]
    x[1] = S.get_random_element()
    x[0] = S.get_random_element_negx(x[1])
    b = randint(0, 1)
    b_, x_ = adv(Dist(S.P), x[b])
    return b_ == b or ((b == 0) and (x_ == x[1]))

def game_b(P, adv, seed=None):
    S = Dist(P, seed=seed)
    x = [0, 0]
    x[1] = S.get_random_element()
    x[0] = S.get_random_element_negx(x[1])
    b = randint(0, 1)
    b_, _ = adv(Dist(S.P), x[b])
    return (b_ == b)

def game_g(P, adv, seed=None):
    S = Dist(P, seed=seed)
    x = [0, 0]
    x[1] = S.get_random_element()
    x[0] = S.get_random_element_negx(x[1])
    b = randint(0, 1)
    _, x_ = adv(Dist(S.P), x[b])
    return (b == 0) and (x_ == x[1])

def game_b_and_g(P, adv, seed=None):
    S = Dist(P, seed=seed)
    x = [0, 0]
    x[1] = S.get_random_element()
    x[0] = S.get_random_element_negx(x[1])
    b = randint(0, 1)
    b_, x_ = adv(Dist(S.P), x[b])
    # print(b_, b == 0, x_ == x[1])
    return (b_ == b) and (b == 0) and (x_ == x[1])

def test_adv(P, adv, trials=16, game=game, seed=None):
    """
    Test `adv` in winning for `P` over `trial` trials.

    :param P: A list of probabilities.
    :param adv: An adversary against the guessing game.
    :param trials: Number of trials.
    :param seed: Explicit seed (optional).
    :returns: Rate of success.

    EXAMPLES:

        sage: set_random_seed(1312)
        sage: P = [0.1, 0.2, 0.3, 0.4]
        sage: test_adv(P, advf, trials=2^16, seed=1337)
        0.627700805664062
        sage: test_adv(P, advf_bad_real, trials=2^16, seed=1337)
        0.540374755859375
        sage: test_adv(P, advf_bad_S, trials=2^16, seed=1337)
        0.540222167968750
        sage: test_adv(P, advf_trivial, trials=2^16, seed=1337)
        0.500167846679688

        sage: set_random_seed(1312)
        sage: P = [0.25, 0.25, 0.25, 0.25]
        sage: test_adv(P, advf, trials=2^16, seed=1312)
        0.499435424804688
        sage: test_adv(P, advf_bad_real, trials=2^16, seed=1312)
        0.496841430664062
        sage: test_adv(P, advf_bad_S, trials=2^16, seed=1312)
        0.624633789062500
        sage: test_adv(P, advf_trivial, trials=2^16, seed=1312)
        0.500167846679688

        sage: set_random_seed(1312)
        sage: P = [0.99, 0.01]
        sage: test_adv(P, advf, trials=2^16, seed=1234)
        0.995132446289062
        sage: test_adv(P, advf_bad_real, trials=2^16, seed=1234)
        0.990127563476562
        sage: test_adv(P, advf_bad_S, trials=2^16, seed=1234)
        0.990127563476562
        sage: test_adv(P, advf_trivial, trials=2^16, seed=1312)
        0.500167846679688

    """

    if seed is None:
        seed = randint(0, 2**31)

    return sum([int(game(P, adv, seed=seed + i)) for i in range(trials)]) / RR(trials)
