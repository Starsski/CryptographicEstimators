# ****************************************************************************
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# ****************************************************************************

from .rqc_constants import (
    RQC_BASE_FIELD_ORDER,
    RQC_DEGREE_EXTENSION,
    RQC_CODE_LENGTH,
    RQC_CODE_DIMENSION,
    RQC_SECRET_KEY_RANK,
    RQC_ERROR_RANK,
)
from ..base_problem import BaseProblem
from ..helper import is_prime_power
from math import log2, ceil


class RQCProblem(BaseProblem):
    def __init__(self, q: int, m: int, n: int, k: int, w: int, w_e: int, **kwargs):
        """Construct an instance of RQCProblem.

        Contains the parameters of the RQC (Rank Quasi-Cyclic) public-key
        encryption scheme.  Security is based on the hardness of decoding
        quasi-cyclic codes in the rank metric.

        Args:
            q (int): Base field order (must be a prime power).
            m (int): Extension degree (F_{q^m} is the ambient field).
            n (int): Code length (number of coordinates over F_{q^m}).
            k (int): Code dimension.
            w (int): Rank weight of the secret key vectors.
            w_e (int): Rank weight of the error/noise vectors used in encryption.
            **kwargs: Additional keyword arguments.
                memory_bound: Maximum allowed memory to use for solving the problem.
                theta (float): Exponent for field-operation cost model (default: 2).

        Examples:
            >>> from cryptographic_estimators.RQCEstimator import RQCProblem
            >>> RQCProblem(q=2, m=127, n=118, k=48, w=7, w_e=7)
            RQC instance with (q, m, n, k, w, w_e) = (2, 127, 118, 48, 7, 7)
        """
        super().__init__(**kwargs)

        if not is_prime_power(q):
            raise ValueError("q must be a prime power")
        if m < 1:
            raise ValueError("m must be >= 1")
        if n < 1:
            raise ValueError("n must be >= 1")
        if k < 1 or k >= n:
            raise ValueError("k must be in the range [1, n-1]")
        if w < 1:
            raise ValueError("w must be >= 1")
        if w_e < 1:
            raise ValueError("w_e must be >= 1")

        theta = kwargs.get("theta", 2)
        # theta=None is valid: the ngates() helper uses a different cost model in that case
        # (2 * log2(q)^2 + log2(q) per multiplication).  This mirrors RankSDProblem.
        if theta is not None and not (0 <= theta <= 2):
            raise ValueError("theta must be either None or 0 <= theta <= 2")

        self.parameters[RQC_BASE_FIELD_ORDER] = q
        self.parameters[RQC_DEGREE_EXTENSION] = m
        self.parameters[RQC_CODE_LENGTH] = n
        self.parameters[RQC_CODE_DIMENSION] = k
        self.parameters[RQC_SECRET_KEY_RANK] = w
        self.parameters[RQC_ERROR_RANK] = w_e
        self._theta = theta

    def to_bitcomplexity_time(self, basic_operations: float):
        """Return the bit-complexity corresponding to a certain amount of basic operations.

        Args:
            basic_operations (float): Number of basic operations (logarithmic).
        """
        from ..helper import ngates
        q = self.parameters[RQC_BASE_FIELD_ORDER]
        return ngates(q, basic_operations, theta=self._theta)

    def to_bitcomplexity_memory(self, elements_to_store: float):
        """Return the memory bit-complexity associated to a given number of elements to store.

        Args:
            elements_to_store (float): Number of elements to store (logarithmic).
        """
        q = self.parameters[RQC_BASE_FIELD_ORDER]
        return log2(ceil(log2(q))) + elements_to_store

    def get_parameters(self):
        """Return the problem parameters.

        Returns:
            list: [q, m, n, k, w, w_e]
        """
        return list(self.parameters.values())

    @property
    def theta(self):
        """Returns the value of `theta`."""
        return self._theta

    @theta.setter
    def theta(self, value: float):
        """Sets the value of `theta`."""
        self._theta = value

    def __repr__(self):
        q, m, n, k, w, w_e = self.get_parameters()
        return (
            "RQC instance with (q, m, n, k, w, w_e) = "
            f"({q}, {m}, {n}, {k}, {w}, {w_e})"
        )
